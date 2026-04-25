"""
AIPET Explain — Claude API Client
Handles all communication with the Anthropic Claude API via the official SDK.

This module is the only place in AIPET that talks to Claude.
All other modules call functions from here — they never
interact with the API directly.

Usage:
    from dashboard.backend.explain.claude_client import generate_explanation
    result = generate_explanation(prompt="Explain this vulnerability...",
                                   system_prompt="You are a security expert.")
"""

import os
import logging

_LOG = logging.getLogger("aipet.claude_client")

CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS   = 1000


def _get_client():
    """Return a configured Anthropic client. Raises EnvironmentError if key missing."""
    import anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Add it to your .env file: ANTHROPIC_API_KEY=your_key_here"
        )
    return anthropic.Anthropic(api_key=api_key)


def generate_explanation(prompt: str, max_tokens: int = MAX_TOKENS,
                          system_prompt: str | None = None) -> dict:
    """
    Sends a prompt to the Claude API and returns the generated text.

    Args:
        prompt:        The user-facing prompt to send to Claude.
        max_tokens:    Maximum tokens in the response (default 1000).
        system_prompt: Optional system instruction (sent in the system field,
                       not prepended to user content).

    Returns on success:
        {
            "success":       True,
            "content":       "The generated text...",
            "input_tokens":  350,
            "tokens_used":   275,     # output tokens (kept for backward compat)
            "model":         "claude-sonnet-4-20250514",
        }

    Returns on failure:
        {
            "success":       False,
            "error":         "Error message",
            "content":       None,
            "input_tokens":  0,
            "tokens_used":   0,
        }
    """
    try:
        client = _get_client()

        kwargs: dict = {
            "model":      CLAUDE_MODEL,
            "max_tokens": max_tokens,
            "messages":   [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        response = client.messages.create(**kwargs)

        content      = response.content[0].text
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        return {
            "success":      True,
            "content":      content,
            "input_tokens": input_tokens,
            "tokens_used":  output_tokens,   # legacy key; callers expect this name
            "model":        CLAUDE_MODEL,
        }

    except EnvironmentError as exc:
        return {"success": False, "error": str(exc), "content": None,
                "input_tokens": 0, "tokens_used": 0}

    except Exception as exc:
        _LOG.exception("generate_explanation: Claude API call failed")
        return {"success": False, "error": str(exc), "content": None,
                "input_tokens": 0, "tokens_used": 0}
