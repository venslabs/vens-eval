import gzip
import json
import unittest

from vkpi.a9 import usage

# Response example of the Chat Completions reference (the API vens calls), read on 2026-11-26:
# https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
OPENAI_REFERENCE_USAGE = {
    "prompt_tokens": 19,
    "completion_tokens": 10,
    "total_tokens": 29,
    "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
    "completion_tokens_details": {
        "reasoning_tokens": 0,
        "audio_tokens": 0,
        "accepted_prediction_tokens": 0,
        "rejected_prediction_tokens": 0,
    },
}

# Response example of the Messages reference, read on 2026-11-26:
# https://platform.claude.com/docs/en/api/messages/create
ANTHROPIC_REFERENCE_USAGE = {
    "cache_creation": {"ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 0},
    "cache_creation_input_tokens": 2051,
    "cache_read_input_tokens": 2051,
    "inference_geo": "global",
    "input_tokens": 2095,
    "output_tokens": 503,
    "output_tokens_details": {"thinking_tokens": 0},
    "server_tool_use": {"web_fetch_requests": 2, "web_search_requests": 0},
    "service_tier": "standard",
    "speed": "standard",
}


def anthropic(**changes):
    return {**ANTHROPIC_REFERENCE_USAGE, **changes}


class OpenAITokens(unittest.TestCase):
    def test_reference_example(self):
        self.assertEqual(usage.tokens("openai", OPENAI_REFERENCE_USAGE), {"input": 19, "cache_read": 0, "output": 10})

    def test_cached_tokens_come_out_of_the_prompt(self):
        # prompt_tokens counts the cached tokens too; reasoning tokens are part of completion_tokens.
        raw = {
            **OPENAI_REFERENCE_USAGE,
            "prompt_tokens": 2006,
            "completion_tokens": 300,
            "prompt_tokens_details": {"cached_tokens": 1920},
            "completion_tokens_details": {"reasoning_tokens": 128},
        }
        self.assertEqual(usage.tokens("openai", raw), {"input": 86, "cache_read": 1920, "output": 300})

    def test_missing_cached_tokens_is_not_measured(self):
        raw = {key: value for key, value in OPENAI_REFERENCE_USAGE.items() if key != "prompt_tokens_details"}
        self.assertIsNone(usage.tokens("openai", raw))

    def test_inconsistent_or_malformed_counts_are_not_measured(self):
        for raw in (
            {**OPENAI_REFERENCE_USAGE, "prompt_tokens_details": {"cached_tokens": 20}},
            {**OPENAI_REFERENCE_USAGE, "completion_tokens": None},
            {**OPENAI_REFERENCE_USAGE, "prompt_tokens": True},
            {**OPENAI_REFERENCE_USAGE, "prompt_tokens": -1},
            {**OPENAI_REFERENCE_USAGE, "prompt_tokens": 19.0},
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(usage.tokens("openai", raw))


class AnthropicTokens(unittest.TestCase):
    def test_reference_example_split_does_not_add_up(self):
        # The reference example reports 2051 cache-write tokens and a 0 + 0 split:
        # the two durations have different prices, so the call is not priced.
        self.assertIsNone(usage.tokens("anthropic", ANTHROPIC_REFERENCE_USAGE))

    def test_cache_writes_split_by_duration(self):
        raw = anthropic(cache_creation={"ephemeral_5m_input_tokens": 2000, "ephemeral_1h_input_tokens": 51})
        self.assertEqual(usage.tokens("anthropic", raw), {
            "input": 2095,
            "cache_write_5m": 2000,
            "cache_write_1h": 51,
            "cache_read": 2051,
            "output": 503,
        })

    def test_no_cache(self):
        raw = anthropic(cache_creation=None, cache_creation_input_tokens=0, cache_read_input_tokens=0)
        self.assertEqual(usage.tokens("anthropic", raw), {
            "input": 2095,
            "cache_write_5m": 0,
            "cache_write_1h": 0,
            "cache_read": 0,
            "output": 503,
        })

    def test_cache_write_without_split_is_not_measured(self):
        self.assertIsNone(usage.tokens("anthropic", anthropic(cache_creation=None)))

    def test_missing_or_null_fields_are_not_measured(self):
        # The reference types both cache fields "number or null".
        for field in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            with self.subTest(field=field):
                raw = {key: value for key, value in ANTHROPIC_REFERENCE_USAGE.items() if key != field}
                self.assertIsNone(usage.tokens("anthropic", raw))
                self.assertIsNone(usage.tokens("anthropic", anthropic(**{field: None})))


class ParseResponse(unittest.TestCase):
    def test_openai_tier_is_next_to_usage(self):
        body = json.dumps({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": "gpt-5.4-mini-2026-03-17",
            "choices": [],
            "usage": OPENAI_REFERENCE_USAGE,
            "service_tier": "default",
        }).encode()
        self.assertEqual(usage.parse_response("openai", body, None), {
            "model_served": "gpt-5.4-mini-2026-03-17",
            "service_tier": "default",
            "usage": OPENAI_REFERENCE_USAGE,
        })

    def test_anthropic_tier_is_inside_usage_and_usage_is_kept_verbatim(self):
        body = gzip.compress(json.dumps({
            "type": "message",
            "model": "claude-sonnet-4-6",
            "usage": ANTHROPIC_REFERENCE_USAGE,
        }).encode())
        self.assertEqual(usage.parse_response("anthropic", body, "gzip"), {
            "model_served": "claude-sonnet-4-6",
            "service_tier": "standard",
            "usage": ANTHROPIC_REFERENCE_USAGE,
        })

    def test_unreadable_bodies_give_no_usage(self):
        empty = {"model_served": None, "service_tier": None, "usage": None}
        for body, encoding in (
            (b"<html>bad gateway</html>", None),
            (b"{}", "br"),
            (b"not gzip", "gzip"),
            (json.dumps({"type": "error", "error": {"type": "overloaded_error"}}).encode(), None),
        ):
            with self.subTest(body=body, encoding=encoding):
                self.assertEqual(usage.parse_response("anthropic", body, encoding), empty)

    def test_requested_model(self):
        self.assertEqual(usage.requested_model(b'{"model": "claude-sonnet-4-6", "max_tokens": 16384}'), "claude-sonnet-4-6")
        self.assertIsNone(usage.requested_model(b"not json"))
        self.assertIsNone(usage.requested_model(b'{"model": 4}'))

    def test_unknown_provider(self):
        self.assertIsNone(usage.tokens("googleai", OPENAI_REFERENCE_USAGE))


if __name__ == "__main__":
    unittest.main()
