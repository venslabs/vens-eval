from __future__ import annotations

import gzip
import json
import zlib

CATEGORIES = ("input", "cache_write_5m", "cache_write_1h", "cache_read", "output")


def requested_model(body: bytes) -> str | None:
    payload = _loads(body)
    model = payload.get("model") if isinstance(payload, dict) else None
    return model if isinstance(model, str) else None


def parse_response(provider: str, body: bytes, content_encoding: str | None) -> dict:
    payload = _decoded_json(body, content_encoding)
    if not isinstance(payload, dict):
        return {"model_served": None, "service_tier": None, "usage": None}
    raw = payload.get("usage")
    raw = raw if isinstance(raw, dict) else None
    # OpenAI reports the tier next to usage, Anthropic inside it.
    tier_holder = payload if provider == "openai" else (raw or {})
    return {
        "model_served": _text(payload.get("model")),
        "service_tier": _text(tier_holder.get("service_tier")),
        "usage": raw,
    }


def tokens(provider: str, usage: dict | None) -> dict | None:
    if not isinstance(usage, dict):
        return None
    if provider == "openai":
        return _openai(usage)
    if provider == "anthropic":
        return _anthropic(usage)
    return None


def _openai(usage: dict) -> dict | None:
    prompt = _count(usage, "prompt_tokens")
    output = _count(usage, "completion_tokens")
    cached = _count(usage.get("prompt_tokens_details"), "cached_tokens")
    if prompt is None or output is None or cached is None or cached > prompt:
        return None
    return {"input": prompt - cached, "cache_read": cached, "output": output}


def _anthropic(usage: dict) -> dict | None:
    counts = {
        "input": _count(usage, "input_tokens"),
        "cache_read": _count(usage, "cache_read_input_tokens"),
        "output": _count(usage, "output_tokens"),
    }
    writes = _cache_writes(usage.get("cache_creation"), _count(usage, "cache_creation_input_tokens"))
    if None in counts.values() or writes is None:
        return None
    return {**counts, "cache_write_5m": writes[0], "cache_write_1h": writes[1]}


def _cache_writes(breakdown: object, total: int | None) -> tuple[int, int] | None:
    # The 5-minute and 1-hour writes have different prices: a total that the
    # breakdown does not account for cannot be priced.
    if total is None:
        return None
    if breakdown is None:
        return (0, 0) if total == 0 else None
    five = _count(breakdown, "ephemeral_5m_input_tokens")
    hour = _count(breakdown, "ephemeral_1h_input_tokens")
    if five is None or hour is None or five + hour != total:
        return None
    return five, hour


def _count(holder: object, key: str) -> int | None:
    value = holder.get(key) if isinstance(holder, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _decoded_json(body: bytes, content_encoding: str | None) -> object:
    encoding = (content_encoding or "identity").strip().lower()
    if encoding == "gzip":
        try:
            body = gzip.decompress(body)
        except (OSError, EOFError, zlib.error):
            return None
    elif encoding != "identity":
        return None
    return _loads(body)


def _loads(body: bytes) -> object:
    try:
        return json.loads(body)
    except ValueError:
        return None
