"""
AIPET Explain — Claude API Client
Handles all communication with the Anthropic Claude API.

This module is the only place in AIPET that talks to Claude.
All other modules call functions from here — they never
interact with the API directly.

Usage:
    from dashboard.backend.explain.claude_client import generate_explanation
    result = generate_explanation(prompt="Explain this vulnerability...")
"""

import os
import json
import urllib.request
import urllib.error


CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"
MAX_TOKENS     = 1000


def get_api_key():
    """
    Retrieves the Claude API key from environment variables.
    Raises a clear error if the key is not set — never fails silently.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Add it to your .env file: ANTHROPIC_API_KEY=your_key_here"
        )
    return api_key


def generate_explanation(prompt, max_tokens=MAX_TOKENS):
    """
    Sends a prompt to the Claude API and returns the generated text.

    Args:
        prompt (str): The prompt to send to Claude
        max_tokens (int): Maximum tokens in the response (default 1000)

    Returns:
        dict: {
            "success": True,
            "content": "The generated text...",
            "tokens_used": 450,
            "model": "claude-sonnet-4-20250514"
        }

        or on failure:
        {
            "success": False,
            "error": "Error message",
            "content": None,
            "tokens_used": 0
        }
    """
    try:
        api_key = get_api_key()

        # Build the request payload
        payload = {
            "model":      CLAUDE_MODEL,
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role":    "user",
                    "content": prompt
                }
            ]
        }

        # Encode payload as JSON bytes
        data = json.dumps(payload).encode("utf-8")

        # Build the HTTP request
        req = urllib.request.Request(
            CLAUDE_API_URL,
            data=data,
            method="POST"
        )
        req.add_header("Content-Type",      "application/json")
        req.add_header("x-api-key",         api_key)
        req.add_header("anthropic-version", "2023-06-01")

        # Send the request and parse the response
        with urllib.request.urlopen(req, timeout=30) as response:
            response_body = response.read().decode("utf-8")
            response_data = json.loads(response_body)

        # Extract the text content from the response
        content    = response_data["content"][0]["text"]
        tokens_used = response_data.get("usage", {}).get("output_tokens", 0)

        return {
            "success":     True,
            "content":     content,
            "tokens_used": tokens_used,
            "model":       CLAUDE_MODEL
        }

    except EnvironmentError as e:
        return {
            "success":     False,
            "error":       str(e),
            "content":     None,
            "tokens_used": 0
        }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else "No response body"
        return {
            "success":     False,
            "error":       f"Claude API HTTP error {e.code}: {error_body}",
            "content":     None,
            "tokens_used": 0
        }

    except urllib.error.URLError as e:
        return {
            "success":     False,
            "error":       f"Failed to reach Claude API: {str(e.reason)}",
            "content":     None,
            "tokens_used": 0
        }

    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return {
            "success":     False,
            "error":       f"Unexpected response format from Claude API: {str(e)}",
            "content":     None,
            "tokens_used": 0
        }

    except Exception as e:
        return {
            "success":     False,
            "error":       f"Unexpected error: {str(e)}",
            "content":     None,
            "tokens_used": 0
        }