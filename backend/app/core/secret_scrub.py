"""
Secret scrubbing for stored / broadcast text.

When the operator hands us a credential and we substitute it into a
command line (impacket, netexec, custom SSH command, C2 BOF args, …),
the rendered string contains the raw secret. That string then ends up
in `HostActivity.command`, `Job.command`, audit-trail metadata and the
WebSocket broadcast that fans the host_activity event out to every
operator with `hosts.read`.

Scrubbing replaces the literal secret bytes in the rendered text with a
fixed placeholder before storage. This is intentionally conservative:
we only scrub values long enough that a substring replace is unlikely
to false-positive against unrelated text (>= 4 chars).

We keep the rendered (unscrubbed) command in memory only — passed
directly to the executor and dropped on completion — so SSH / C2
connectors still get the real value.
"""

from __future__ import annotations

REDACTED = "***REDACTED***"
_MIN_SCRUBBABLE_LEN = 4


def scrub_secret(text: str, secret: str | None) -> str:
    """Return `text` with all occurrences of `secret` replaced by ***REDACTED***.

    No-op if either input is empty / None or if the secret is shorter than
    4 characters (avoids false-positive replacements in unrelated text).
    """
    if not text or not secret:
        return text
    s = secret.strip()
    if len(s) < _MIN_SCRUBBABLE_LEN:
        return text
    return text.replace(s, REDACTED)


def scrub_secrets(text: str, *secrets: str | None) -> str:
    """Scrub multiple secrets sequentially (longest first to avoid partial overlaps)."""
    if not text:
        return text
    ordered = sorted(
        (s for s in secrets if s and len(s.strip()) >= _MIN_SCRUBBABLE_LEN),
        key=lambda x: len(x),
        reverse=True,
    )
    for s in ordered:
        text = text.replace(s.strip(), REDACTED)
    return text


def scrub_for_cred(text: str, cred: dict | None) -> str:
    """Scrub a rendered command using `cred.secret` (the only sensitive field)."""
    if not cred:
        return text
    return scrub_secret(text, cred.get("secret"))
