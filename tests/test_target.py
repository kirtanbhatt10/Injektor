import json
import httpx

from injector.config import TargetConfig
from injector.target import OpenAICompatibleTarget


def test_mocked_endpoint_roundtrip():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "local mock response"}}]})

    transport = httpx.MockTransport(handler)
    cfg = TargetConfig("http://127.0.0.1:8765/v1/chat/completions", "mock")
    assert OpenAICompatibleTarget(cfg, transport=transport).ask("hello") == "local mock response"
    assert seen["body"]["messages"][0]["content"] == "hello"
