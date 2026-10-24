import hashlib
import json
import os
import re
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types
from groq import Groq

load_dotenv()

GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
PRIMARY = os.getenv("PRIMARY_PROVIDER", "groq")
CACHE_DIR = Path(".cache/llm")
USAGE_LOG = Path("evaluation/usage_log.jsonl")
MAX_ATTEMPTS = 3


class LLMRouter:
    def __init__(self, primary=PRIMARY):
        self.primary = primary
        self.groq = Groq(api_key=os.environ["GROQ_API_KEY"]) if os.getenv("GROQ_API_KEY") else None
        self.gemini = genai.Client(api_key=os.environ["GEMINI_API_KEY"]) if os.getenv("GEMINI_API_KEY") else None
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)

    def _key(self, system, user, images, json_mode):
        digest = hashlib.sha256()
        digest.update(json.dumps([system, user, json_mode]).encode())
        for data, mime in images:
            digest.update(mime.encode())
            digest.update(data)
        return digest.hexdigest()

    def _log(self, provider, model, tokens_in, tokens_out, purpose):
        row = {
            "ts": time.time(),
            "provider": provider,
            "model": model,
            "input_tokens": tokens_in,
            "output_tokens": tokens_out,
            "purpose": purpose,
        }
        with USAGE_LOG.open("a") as handle:
            handle.write(json.dumps(row) + "\n")

    def _call_groq(self, system, user, json_mode):
        kwargs = {
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        response = self.groq.chat.completions.create(**kwargs)
        usage = response.usage
        return response.choices[0].message.content, GROQ_MODEL, usage.prompt_tokens, usage.completion_tokens

    def _call_gemini(self, system, user, images, json_mode):
        parts = [types.Part.from_bytes(data=data, mime_type=mime) for data, mime in images]
        parts.append(types.Part.from_text(text=user))
        config = types.GenerateContentConfig(
            system_instruction=system,
            temperature=0,
            response_mime_type="application/json" if json_mode else "text/plain",
        )
        response = self.gemini.models.generate_content(
            model=GEMINI_MODEL,
            contents=parts,
            config=config,
        )
        meta = response.usage_metadata
        return response.text, GEMINI_MODEL, meta.prompt_token_count or 0, meta.candidates_token_count or 0

    def _attempt(self, provider, system, user, images, json_mode):
        last_error = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                if provider == "groq":
                    return self._call_groq(system, user, json_mode)
                return self._call_gemini(system, user, images, json_mode)
            except Exception as error:
                last_error = error
                time.sleep(2 ** (attempt + 1))
        raise last_error

    def _order(self, images):
        if images:
            return ["gemini"]
        other = "gemini" if self.primary == "groq" else "groq"
        order = [self.primary, other]
        available = {"groq": self.groq, "gemini": self.gemini}
        return [name for name in order if available[name] is not None]

    def complete(self, system, user, images=None, json_mode=True, purpose="general"):
        images = images or []
        key = self._key(system, user, images, json_mode)
        cache_file = CACHE_DIR / f"{key}.json"
        if cache_file.exists():
            return json.loads(cache_file.read_text())["text"]
        errors = []
        for provider in self._order(images):
            try:
                text, model, tokens_in, tokens_out = self._attempt(provider, system, user, images, json_mode)
            except Exception as error:
                errors.append(f"{provider}: {error}")
                continue
            self._log(provider, model, tokens_in, tokens_out, purpose)
            cache_file.write_text(json.dumps({"text": text, "provider": provider}))
            return text
        raise RuntimeError("; ".join(errors) or "no provider available")

    def complete_json(self, system, user, images=None, purpose="general"):
        text = self.complete(system, user, images=images, json_mode=True, purpose=purpose)
        cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
        return json.loads(cleaned)

    @staticmethod
    def usage_summary():
        totals = {}
        if not USAGE_LOG.exists():
            return totals
        for line in USAGE_LOG.read_text().splitlines():
            row = json.loads(line)
            bucket = totals.setdefault(row["model"], {"calls": 0, "input_tokens": 0, "output_tokens": 0})
            bucket["calls"] += 1
            bucket["input_tokens"] += row["input_tokens"]
            bucket["output_tokens"] += row["output_tokens"]
        return totals


if __name__ == "__main__":
    router = LLMRouter()
    reply = router.complete_json(
        "Reply with JSON only.",
        'Return {"ok": true, "provider_test": "hello"}',
        purpose="smoke_test",
    )
    print(reply)
    print(LLMRouter.usage_summary())