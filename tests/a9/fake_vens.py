#!/usr/bin/env python3
# Stands in for vens in the run tests: it calls the provider through the base
# URL vens reads, then writes the VEX the way vens does, to a temp file renamed
# into place.
import http.client
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROUTES = {
    "openai": ("OPENAI_BASE_URL", "chat/completions", "OPENAI_MODEL", "gpt-5.4-mini"),
    "anthropic": ("ANTHROPIC_BASE_URL", "v1/messages", "ANTHROPIC_MODEL", "claude-sonnet-4-6"),
}


def main(args):
    base_var, path, model_var, default_model = ROUTES[args[args.index("--llm") + 1]]
    base = urlsplit(os.environ[base_var])
    body = json.dumps({"model": os.environ.get(model_var) or default_model, "messages": []}).encode()
    for _ in range(int(os.environ.get("FAKE_VENS_CALLS", "1"))):
        conn = http.client.HTTPConnection(base.hostname, base.port, timeout=10)
        conn.request("POST", base.path + path, body=body,
                     headers={"Content-Type": "application/json", "X-Stainless-Retry-Count": "0"})
        conn.getresponse().read()
        conn.close()
    code = int(os.environ.get("FAKE_VENS_EXIT", "0"))
    if code == 0:
        vex = Path(args[-1])
        temp = vex.with_name(".vens-test.tmp")
        temp.write_text('{"bomFormat": "CycloneDX"}\n')
        os.replace(temp, vex)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
