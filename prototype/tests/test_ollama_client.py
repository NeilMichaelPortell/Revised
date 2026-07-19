"""Regression tests for the local Ollama subprocess fallback."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from ai.ollama_client import _try_subprocess


class OllamaSubprocessTests(TestCase):
    @patch("ai.ollama_client.subprocess.run")
    def test_unicode_prompt_is_sent_as_utf8(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                '{"title":"Test","what_happened":"USB connected",'
                '"why_risky":"Risk","how_to_prevent":["Review it"],'
                '"learning_tip":"Be careful"}'
            ),
            stderr="",
        )

        result = _try_subprocess("llama3:latest", "USB — Żółć 漢字 🔒")

        self.assertEqual(result["title"], "Test")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertIn("🔒", kwargs["input"])

