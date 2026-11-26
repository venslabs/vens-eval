"""What an attempt's calls cost, estimated per kind of call.

vens records no provider usage at either measured commit, so no record vens writes holds a call's tokens. The
measured cost is the providers' usage exports, per campaign, day, key and model; this module gives only the
estimate beside it, from each archived call's prompts and reply, never added to the measured totals.
"""
import re

# List prices per 1M tokens (input, output), standard tier.
PRICES = {"gpt-5.4-mini": (0.75, 4.50), "claude-sonnet-4-6": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0)}
CHARS_PER_TOKEN = 4.0
LABEL = ("estimate, not measured: each archived call's prompt and reply characters at 4 per token and the model's "
         "list price, the JSON schema sent with each call not counted")


def price(model):
    """(input, output) dollars per 1M tokens, a dated snapshot (OpenAI's -YYYY-MM-DD, Anthropic's -YYYYMMDD) priced as
    its model; None for a model not listed."""
    return PRICES.get(re.sub(r"-(\d{4}-\d{2}-\d{2}|\d{8})$", "", model or ""))


def _chars(raw):
    return 0 if raw is None else len(raw.decode("utf-8", errors="replace"))


def estimate(archived, kinds, model):
    """{label, model, by_kind, total, calls_without_reply, why}. A call without an archived reply is counted at its
    prompts alone. Every figure is None when the model has no list price here or no call is archived."""
    p = price(model)
    out = {"label": LABEL, "model": model, "by_kind": None, "total": None, "calls_without_reply": None, "why": None}
    if archived is None:
        return {**out, "why": "no archived calls"}
    if p is None:
        return {**out, "why": f"no list price for {model!r}"}
    by_kind = {}
    for call, kind in zip(archived, kinds or [None] * len(archived)):
        usd = ((_chars(call.system) + _chars(call.human)) / CHARS_PER_TOKEN * p[0]
               + _chars(call.response) / CHARS_PER_TOKEN * p[1]) / 1e6
        key = kind or "unclassified"
        by_kind = {**by_kind, key: by_kind.get(key, 0.0) + usd}
    return {**out, "by_kind": by_kind, "total": sum(by_kind.values()),
            "calls_without_reply": sum(1 for c in archived if c.response is None)}
