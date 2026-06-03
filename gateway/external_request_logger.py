"""
External Request Logger

Logs all agent-initiated external HTTP/web search requests to a configured
Slack channel. This runs at the infrastructure level — the LLM never sees
these logs.

Hook points:
  1. model_tools.py  → post-tool-call hook (catches web_search, browser,
     web_extract, send_message, cronjob, youtube-content, spotify, etc.)
  2. terminal_tool.py → pre-execution filter (catches curl, wget, python
     requests/httpx, node-fetch, etc.)

Usage:
  from gateway.external_request_logger import log_external_request
  log_external_request(tool_name, args, result, task_id)

  from gateway.external_request_logger import should_log_terminal_command
  should_log_terminal_command(command)  # returns True if command looks external
"""

import json
import logging
import os
import re
import time
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (read from gateway config / env at runtime)
# ---------------------------------------------------------------------------

_LOG_CHANNEL_ENV = "HERMES_EXTERNAL_REQUEST_LOG_CHANNEL"

# Tools that always trigger a log entry
_EXTERNAL_TOOL_NAMES: Set[str] = frozenset({
    # Web search / extraction
    "web_search", "web_extract", "web_extract_pwsh",
    # Browser automation
    "browser_navigate", "browser_click", "browser_type", "browser_press",
    "browser_snapshot", "browser_back", "browser_scroll", "browser_vision",
    "browser_get_images",
    # Messaging (sends external HTTP)
    "send_message", "send_message_to_platform",
    # Cron / scheduling
    "cronjob", "delegate_task",
    # YouTube
    "youtube_content",
    # Spotify
    "spotify",
    # Polymarket
    "polymarket",
    # GitHub
    "gh", "github_auth", "github_code_review", "github_issues",
    "github_pr_workflow", "github_repo_management",
    # Email
    "himalaya",
    # Google Workspace
    "google_workspace",
    # Linear
    "linear",
    # Notion
    "notion",
    # Airtable
    "airtable",
    # OCR
    "ocr_and_documents",
    # Maps
    "maps",
    # Nano PDF
    "nano_pdf",
    # Music / audio
    "songsee", "songwriting_and_ai_music", "heartmula",
    # GIF search
    "gif_search",
    # ComfyUI
    "comfyui",
    # LLaMA.cpp / HuggingFace
    "llama_cpp", "huggingface_hub",
    # W&B
    "weights_and_biases",
    # DSPy
    "dspy",
    # Arxiv
    "arxiv",
    # Blogwatcher
    "blogwatcher",
    # LLM Wiki
    "llm_wiki",
    # Minecraft
    "minecraft_server",
    # TouchDesigner
    "touchdesigner_mcp",
    # OpenHue / Home Assistant
    "openhue", "homeassistant",
    # Vision
    "vision_analyze",
    # Text to speech
    "text_to_speech",
    # Code execution
    "execute_code",
    # Skill / memory / session
    "skill_manage", "skill_view", "skills_list",
    "memory", "session_search",
    # Webhook subscriptions
    "webhook_subscriptions",
    # Search / Todo / Kanban
    "search", "todo", "kanban",
    # Debugging / Node inspect
    "debugging_hermes_tui_commands", "node_inspect_debugger",
    # Plan / spike / TDD
    "plan", "spike", "test_driven_development",
    "writing_plans", "requesting_code_review",
    # Subagent-driven development
    "subagent_driven_development",
    # Context status
    "context_status",
    # Humanizer
    "humanizer",
    # Design tools
    "claude_design", "popular_web_designs", "sketch",
    "architecture_diagram", "excalidraw", "p5js",
    # Image generation
    "image_gen",
    # Pixel art
    "pixel_art",
    # ASCII art / video
    "ascii_art", "ascii_video",
    # Manim video
    "manim_video",
    # Baoyu
    "baoyu_comic", "baoyu_infographic",
    # Design MD
    "design_md",
    # OpenClaw imports
    "self_learning",
    # Red teaming
    "godmode",
    # Windows BSOD
    "windows_bsod_diagnosis",
    # Pokemon
    "pokemon_player",
    # OpenClaw
    "openclaw_imports",
    # Powerpoint
    "powerpoint",
    # Obsidian
    "obsidian",
})

# Terminal command patterns that indicate HTTP/network requests
_TERMINAL_HTTP_RE = re.compile(
    r"\b(curl|wget|httpie|fetch|python\s+-c|python\s+.*\.(requests|httpx|urllib)"
    r"|node\s+.*fetch|axios|go\s+.*http|php\s+.*curl"
    r"|powershell\s+.*Invoke-WebRequest|Invoke-WebRequest"
    r"|npm\s+(request|got|superagent)"
    r"|pip\s+(install|download|wheel)"
    r"|apt-get|apt\s+install|yum|dnf|pacman|apk\s+add"
    r"|choco\s+install|scoop\s+install|winget\s+install"
    r"|brew\s+(install|upgrade)"
    r"|git\s+(clone|pull|fetch)"
    r"|docker\s+(pull|push|build)"
    r"|terraform\s+(apply|plan)"
    r"|ansible|puppet|chef"
    r"|rsync|scp|sftp)",
    re.IGNORECASE,
)

# Docker registries that are NOT external (local/dev registries)
_DOCKER_LOCAL_MARKERS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "192.168.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
]

# Commands to NEVER log (noise reduction)
_TERMINAL_EXCLUSIONS = [
    "ls", "dir", "tree", "find", "grep", "rg", "cat", "head", "tail",
    "echo", "print", "printf",
    "date", "time", "whoami", "hostname", "uname",
    "pwd", "cd", "env", "set", "export",
    "python --version", "node --version", "npm --version",
    "git status", "git diff", "git log",
    "hermes", "openclaw",
    "ps", "tasklist", "top", "htop",
    "df", "du", "free",
    "ping", "nslookup", "dig", "traceroute",
]

# ---------------------------------------------------------------------------
# Local/private URL detection (for terminal command filtering)
# ---------------------------------------------------------------------------

# Regex to extract URLs from command strings
_URL_EXTRACT_RE = re.compile(r"https?://[^\s'\"]+")

# Localhost / loopback / private IP prefixes
_LOCAL_URL_MARKERS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "192.168.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
]


def _is_local_url(url: str) -> bool:
    """Check if a URL points to a local or private address."""
    url_lower = url.lower()
    return any(marker in url_lower for marker in _LOCAL_URL_MARKERS)


def _has_external_url(command: str) -> bool:
    """Check if a command contains any URLs pointing to external addresses.

    Returns True if the command has at least one external URL.
    Returns False if all URLs are local/private, or if no URLs are found.
    """
    urls = _URL_EXTRACT_RE.findall(command)
    if not urls:
        return False
    # If ANY URL is external, the command is worth logging
    return any(not _is_local_url(url) for url in urls)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_log_channel: Optional[str] = None
_log_enabled: bool = False
_lock = threading.Lock()
_last_log_attempt: float = 0.0
_LOG_COOLDOWN = 1.0  # seconds between Slack posts (rate limit safety)


def configure(
    channel: str,
    enabled: bool = True,
) -> None:
    """Configure the external request logger.

    Args:
        channel: Slack channel ID to log to (e.g. 'C0B7Z4L6XDL').
        enabled: Whether logging is active.
    """
    global _log_channel, _log_enabled
    with _lock:
        _log_channel = channel
        _log_enabled = enabled
    logger.info(
        "External request logger configured: channel=%s enabled=%s",
        channel, enabled,
    )


def is_enabled() -> bool:
    """Check if the logger is active."""
    with _lock:
        return _log_enabled and _log_channel is not None


def get_channel() -> Optional[str]:
    """Return the configured Slack channel."""
    with _lock:
        return _log_channel


def _load_config() -> None:
    """Load configuration from environment or gateway config."""
    global _log_channel, _log_enabled

    # Check env var first
    env_channel = os.environ.get(_LOG_CHANNEL_ENV)
    if env_channel:
        _log_channel = env_channel
        _log_enabled = True
        logger.info("External request logger enabled via env var: %s", env_channel)
        return

    # Try to load from gateway config
    try:
        from hermes_cli.config import load_config
        cfg = load_config()
        ext_log = getattr(cfg, "external_request_logging", None)
        if ext_log and ext_log.get("enabled"):
            _log_enabled = True
            _log_channel = ext_log.get("slack_channel") or ext_log.get("channel")
            if _log_channel:
                logger.info(
                    "External request logger configured from config: %s",
                    _log_channel,
                )
    except Exception:
        pass  # Config not available yet — may be loaded later


# Load config at module import time
_load_config()


# ---------------------------------------------------------------------------
# Tool call logging
# ---------------------------------------------------------------------------


def should_log_tool_call(function_name: str) -> bool:
    """Return True if this tool call should be logged."""
    if not is_enabled():
        return False
    if function_name in _EXTERNAL_TOOL_NAMES:
        return True
    # Also log any tool that starts with common external-action prefixes
    for prefix in ("web_", "browser_", "send_", "spotify", "youtube",
                   "polymarket", "github", "himalaya", "linear", "notion",
                   "airtable", "ocr", "maps", "nano", "songsee", "heartmula",
                   "gif_search", "comfyui", "llama", "huggingface", "wandb",
                   "dspy", "arxiv", "blogwatcher", "minecraft", "openhue",
                   "homeassistant", "vision", "text_to_speech", "playwright"):
        if function_name.startswith(prefix):
            return True
    return False


def format_tool_log(
    tool_name: str,
    args: Dict[str, Any],
    result_summary: str,
    task_id: str = "",
    duration_ms: int = 0,
) -> str:
    """Format a tool call log entry for Slack."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    args_str = _truncate_args(args)

    result_preview = result_summary[:200] if result_summary else "(no result)"
    if len(result_summary) > 200:
        result_preview += "..."

    lines = [
        "🌐 *External Request*",
        f"📅 {now}",
        f"🔧 Tool: `{tool_name}`",
        f"⏱ Duration: {duration_ms}ms",
    ]
    if task_id:
        lines.append(f"🆔 Task: `{task_id[:12]}...`")
    lines.append(f"📤 Args: {args_str}")
    lines.append(f"📥 Result: {result_preview}")
    lines.append("")

    return "\n".join(lines)


def _truncate_args(args: Dict[str, Any]) -> str:
    """Truncate args dict for Slack display."""
    if not args:
        return "{}"
    try:
        s = json.dumps(args, ensure_ascii=False, default=str)
        if len(s) > 200:
            s = s[:197] + "..."
        return s
    except Exception:
        return str(args)[:200]


def _try_post_to_slack(message: str) -> bool:
    """Send a message to the configured Slack channel.

    Uses the Slack API directly via the Slack SDK's WebClient.
    Returns True if successful, False otherwise.
    """
    global _last_log_attempt
    channel = get_channel()
    if not channel:
        return False

    # Rate limit: don't post more than once per second
    now = time.monotonic()
    if now - _last_log_attempt < _LOG_COOLDOWN:
        return False
    _last_log_attempt = now

    try:
        from slack_sdk.web import WebClient
        from slack_sdk.errors import SlackApiError

        token = os.environ.get("SLACK_BOT_TOKEN", "")
        if not token:
            logger.debug("No SLACK_BOT_TOKEN found, skipping Slack log post")
            return False

        client = WebClient(token=token)
        client.chat_postMessage(channel=channel, text=message)
        return True
    except SlackApiError as e:
        logger.warning("Failed to post external request log to Slack: %s", e)
        return False
    except Exception as e:
        logger.debug("Slack log post error: %s", e)
        return False


def log_external_request(
    tool_name: str,
    args: Dict[str, Any],
    result: str = "",
    task_id: str = "",
    duration_ms: int = 0,
) -> None:
    """Log an external request to the configured Slack channel.

    Called from model_tools.py after every tool call that matches
    the external request criteria.

    Args:
        tool_name: The name of the tool that was called.
        args: The arguments passed to the tool.
        result: The result string returned by the tool.
        task_id: The task/session ID.
        duration_ms: How long the tool took to execute.
    """
    if not is_enabled():
        return

    try:
        message = format_tool_log(tool_name, args, result, task_id, duration_ms)
        _try_post_to_slack(message)
    except Exception as e:
        logger.debug("Error formatting external request log: %s", e)


# ---------------------------------------------------------------------------
# Terminal command logging
# ---------------------------------------------------------------------------


def should_log_terminal_command(command: str) -> bool:
    """Return True if this terminal command makes an external network request.

    Two-stage filter:
      1. Does the command use HTTP/network tools? (curl, wget, python requests, etc.)
      2. Does any URL in the command point to an external address?

    Commands that only contact localhost, 127.0.0.1, or private IPs are excluded.
    Docker pull/push are checked separately (no http:// prefix).
    """
    if not is_enabled():
        return False
    if not command or len(command.strip()) < 3:
        return False

    cmd_lower = command.lower().strip()
    for excl in _TERMINAL_EXCLUSIONS:
        if cmd_lower.startswith(excl):
            return False

    # Stage 1: Is this an HTTP/network-related command?
    if not _TERMINAL_HTTP_RE.search(command):
        return False

    # Stage 2: Does it actually go external?
    # (curl http://localhost:8080 → skip, curl https://api.example.com → log)
    if _has_external_url(command):
        return True

    # Special case: docker pull/push (no http:// prefix on registry names)
    docker_match = re.search(
        r"\bdocker\s+(pull|push)\s+(\S+)", command, re.IGNORECASE
    )
    if docker_match:
        registry = docker_match.group(2)
        return not any(m in registry.lower() for m in _DOCKER_LOCAL_MARKERS)

    return False


def format_terminal_log(
    command: str,
    output: str = "",
    exit_code: int = 0,
    task_id: str = "",
    duration_ms: int = 0,
) -> str:
    """Format a terminal command log entry for Slack."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    cmd_display = command[:150]
    if len(command) > 150:
        cmd_display += "..."

    out_display = output[:300] if output else "(no output)"
    if len(output) > 300:
        out_display += "..."

    status = "✅" if exit_code == 0 else f"❌ (exit {exit_code})"

    lines = [
        "💻 *Terminal External Request*",
        f"📅 {now}",
        f"🔧 Command: `{cmd_display}`",
        f"⏱ Duration: {duration_ms}ms",
        f"📊 Status: {status}",
        f"📥 Output: {out_display}",
        "",
    ]

    return "\n".join(lines)


def log_terminal_request(
    command: str,
    output: str = "",
    exit_code: int = 0,
    task_id: str = "",
    duration_ms: int = 0,
) -> None:
    """Log a terminal command that made an external request."""
    if not is_enabled():
        return

    try:
        message = format_terminal_log(
            command, output, exit_code, task_id, duration_ms,
        )
        _try_post_to_slack(message)
    except Exception as e:
        logger.debug("Error formatting terminal log: %s", e)
