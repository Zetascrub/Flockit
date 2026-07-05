import json
import unittest
from unittest.mock import patch

from utils.ai_client import AIClient
from utils.config import AIProviderConfig


class FakeStreamResponse:
    def iter_lines(self, decode_unicode=True):
        yield json.dumps({"message": {"content": "ok"}})


class AIClientTests(unittest.TestCase):
    def test_ollama_chat_uses_default_or_report_model(self):
        config = AIProviderConfig(
            ollama_model="qwen3:8b",
            ollama_report_model="qwen3:14b",
        )
        client = AIClient(config)

        with patch("utils.ai_client.requests.post", return_value=FakeStreamResponse()) as post:
            self.assertEqual(client.chat("system", "user"), "ok")
            self.assertEqual(post.call_args.kwargs["json"]["model"], "qwen3:8b")

            self.assertEqual(client.chat("system", "user", use_report_model=True), "ok")
            self.assertEqual(post.call_args.kwargs["json"]["model"], "qwen3:14b")


if __name__ == "__main__":
    unittest.main()
