"""
Ollama Client  —  supports qwen3:8b and gpt-oss:20b
─────────────────────────────────────────────────────
Model-specific behaviour:

  qwen3:8b
    • /nothink prefix suppresses chain-of-thought (3x faster for JSON tasks)
    • <think>...</think> blocks stripped as a safety net
    • temperature 0 — deterministic JSON output

  gpt-oss:20b
    • No /nothink (doesn't understand the directive)
    • No think-block stripping needed
    • temperature 0.3 — needs slight variance to avoid repetition loops

  Any other model
    • Safe defaults, no special prefixes

Flow:
  1. Try REST API  (POST /api/chat, Ollama ≥ 0.1.14)  — preferred
  2. Fall back to subprocess  (ollama run)              — universal
"""

import json
import re
import sys
import subprocess
import urllib.request
import urllib.error

import config
from ai.ai_prompts import build_prompt, build_combined_prompt

CREATE_NO_WINDOW = 0x08000000

REQUIRED_FIELDS = {"title", "what_happened", "why_risky", "how_to_prevent", "learning_tip"}
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


# ─── Model helpers ───────────────────────────────────────────────────────────

def _is_qwen3(model: str) -> bool:
    return "qwen3" in model.lower()


def _model_options(model: str) -> dict:
    """
    Ollama generation options tuned per model family.

    qwen3:8b    — temperature 0 (deterministic JSON), 512 tokens
    gpt-oss:20b — temperature 0.3 (avoids repetition loops), 512 tokens
    others      — safe defaults
    """
    m = model.lower()
    if "qwen3" in m:
        return {"temperature": 0,   "num_predict": 512, "top_p": 0.9}
    if "gpt-oss" in m:
        return {"temperature": 0.3, "num_predict": 512, "top_p": 0.95}
    return     {"temperature": 0.3, "num_predict": 512}


def _user_prompt_for_model(model: str, user_prompt: str) -> str:
    """
    Prepend /nothink for Qwen3 only.
    gpt-oss:20b and other models receive the prompt unmodified.
    """
    if _is_qwen3(model):
        return "/nothink\n\n" + user_prompt
    return user_prompt


# ─── Public entry point ──────────────────────────────────────────────────────

def ask_ai(threat: dict, session=None) -> dict:
    """
    Call Ollama and return a structured 5-section dict.
    Reads config.OLLAMA_MODEL at call time so hot-reloads work.
    """
    model = config.OLLAMA_MODEL
    if not model:
        return _error_response("No model selected — restart and choose a model.")

    system_prompt, user_prompt = build_prompt(threat, session)

    result = _try_rest_api(model, system_prompt, user_prompt)
    if result:
        return result

    combined = build_combined_prompt(threat, session)
    result = _try_subprocess(model, combined)
    if result:
        return result

    return _error_response(
        "Ollama returned no usable response. "
        "Make sure 'ollama serve' is running and the model is pulled."
    )


# ─── REST API path ───────────────────────────────────────────────────────────

def _try_rest_api(model: str, system_prompt: str, user_prompt: str) -> dict | None:
    payload = json.dumps({
        "model"  : model,
        "stream" : False,
        "options": _model_options(model),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": _user_prompt_for_model(model, user_prompt)},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:11434/api/chat",
        data    = payload,
        headers = {"Content-Type": "application/json"},
        method  = "POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=config.OLLAMA_TIMEOUT) as resp:
            raw_resp = resp.read().decode("utf-8")
        data = json.loads(raw_resp)
        text = data.get("message", {}).get("content", "").strip()
        if not text:
            return None
        if _is_qwen3(model):
            text = _strip_thinking(text)
        return _parse_and_validate(text)
    except (urllib.error.URLError, OSError):
        return None
    except Exception:
        return None


# ─── Subprocess fallback ─────────────────────────────────────────────────────

def _try_subprocess(model: str, combined_prompt: str) -> dict | None:
    prompt_to_send = _user_prompt_for_model(model, combined_prompt)

    try:
        flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0

        proc = subprocess.run(
            ["ollama", "run", model],
            input          = prompt_to_send,
            capture_output = True,
            text           = True,
            # Windows otherwise uses the active ANSI code page (commonly
            # cp1252), which cannot encode many characters used in prompts.
            encoding       = "utf-8",
            errors         = "replace",
            timeout        = config.OLLAMA_TIMEOUT,
            creationflags  = flags,
        )

        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            return _error_response(
                f"Ollama exited with code {proc.returncode}: {err[:200]}"
            )

        raw = proc.stdout.strip()
        if not raw:
            return _error_response("Ollama returned an empty response.")

        if _is_qwen3(model):
            raw = _strip_thinking(raw)

        result = _parse_and_validate(raw)
        if result:
            return result

        return {"raw_response": raw[:800]}

    except subprocess.TimeoutExpired:
        return _error_response(
            f"Ollama timed out after {config.OLLAMA_TIMEOUT}s. "
            "Is Ollama running?  Try: ollama serve"
        )
    except FileNotFoundError:
        return _error_response(
            "Ollama not found in PATH. "
            "Install from https://ollama.com and run: ollama serve"
        )
    except Exception as exc:
        return _error_response(str(exc))


# ─── Qwen3 think-block stripper ──────────────────────────────────────────────

def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks emitted by Qwen3."""
    cleaned = _THINK_RE.sub("", text).strip()
    return "\n".join(line for line in cleaned.splitlines() if line.strip()) if cleaned else text


# ─── JSON parser ─────────────────────────────────────────────────────────────

def _parse_and_validate(text: str) -> dict | None:
    strategies = [
        lambda t: json.loads(t),
        lambda t: json.loads(
            re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.DOTALL).group(1)
        ),
        lambda t: json.loads(
            re.search(r"\{.*\}", t, re.DOTALL).group(0)
        ),
        lambda t: json.loads(
            re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", t, re.DOTALL)[-1]
        ),
    ]

    for fn in strategies:
        try:
            obj = fn(text)
            if not isinstance(obj, dict):
                continue
            if not REQUIRED_FIELDS.issubset(obj.keys()):
                continue
            htp = obj.get("how_to_prevent", [])
            if isinstance(htp, str):
                obj["how_to_prevent"] = [
                    line.lstrip("•-–*123456789. ").strip()
                    for line in htp.splitlines()
                    if line.strip()
                ]
            # Preserve the exact raw text the model returned so the validation
            # layer can measure JSON-parse vs strict-schema validity against the
            # dissertation's expected classification schema. Never used by the
            # normal display path.
            obj["_raw_text"] = text
            return obj
        except Exception:
            pass

    return None


# ─── Error response ──────────────────────────────────────────────────────────

def _error_response(reason: str) -> dict:
    return {
        "title"         : "Security alert detected",
        "what_happened" : "A security event was flagged on your computer.",
        "why_risky"     : "Review the WHAT WAS DETECTED section above for the specific details.",
        "how_to_prevent": [
            "Make sure Ollama is running: ollama serve",
            "Review the full alert in outputs/security_alerts.txt",
        ],
        "learning_tip"  : f"AI coach unavailable: {reason}",
        "_error"        : True,
    }
