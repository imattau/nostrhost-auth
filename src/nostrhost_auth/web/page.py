"""Loads the static `/nostr-login` and `/nostr-account` pages (PLAN.md
Phase 5/6/7), and the static JS assets they both load for NIP-46 (PLAN.md
Phase 10) - see vendor/nostr-connect/ for how nostr-connect-vendor.js
itself is built.

Each page does all its work client-side against this daemon's own JSON
API - this module just serves the static files, once, cached.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

# PLAN.md Phase 13: "strict CSP on Nostr login page." Matches the policy
# YunoHost's own nginx config applies to /yunohost/sso/ (see
# PHASE0_INVESTIGATION.md) - same shape, since this page has the same
# threat model (a login surface).
#
# connect-src adds 'wss:' (beyond the 'self' every other directive falls
# back to) for Phase 10's NIP-46 support: the client has to open a
# WebSocket to whatever relay a bunker:// link names, or to this page's
# own default relay list for the nostrconnect:// QR flow - both are
# inherently third-party origins we can't pin down to a fixed allowlist.
#
# script-src is 'self' only, no 'unsafe-inline' - PLAN.md Phase 13's
# "strict CSP" is only as strict as this directive, since it's the one
# that actually blocks arbitrary injected <script>/onclick=.../javascript:
# execution. Both pages' logic lives in the external nostr-*-page.js files
# under web/static/ specifically so this can be 'self'-only; keep it that
# way rather than adding an inline <script> back. style-src keeps
# 'unsafe-inline' - both pages still use inline <style> blocks and style="
# ..." attributes, and CSS injection isn't in the same severity class as
# script injection for this threat model.
CONTENT_SECURITY_POLICY = (
    "upgrade-insecure-requests; default-src 'self'; connect-src 'self' wss:; "
    "style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "object-src 'none'; img-src 'self' data:;"
)

_STATIC_CONTENT_TYPES = {
    "nostr-connect-vendor.js": "application/javascript",
    "nostr-passkey-vendor.js": "application/javascript",
    "nostr-connect-ui.js": "application/javascript",
    "nostr-login-page.js": "application/javascript",
    "nostr-account-page.js": "application/javascript",
    "nostr-admin-page.js": "application/javascript",
}


@lru_cache(maxsize=1)
def render_login_page() -> str:
    return resources.files(__package__).joinpath("nostr_login.html").read_text()


@lru_cache(maxsize=1)
def render_account_page() -> str:
    return resources.files(__package__).joinpath("nostr_account.html").read_text()


@lru_cache(maxsize=1)
def render_admin_page() -> str:
    return resources.files(__package__).joinpath("nostr_admin.html").read_text()


@lru_cache(maxsize=None)
def read_static_asset(filename: str) -> bytes:
    """Read one of the known static assets under web/static/.

    `filename` must be one of `_STATIC_CONTENT_TYPES`'s keys - callers are
    expected to validate against that, not pass arbitrary user input; this
    isn't a general-purpose static file server.
    """
    return resources.files(__package__).joinpath("static", filename).read_bytes()


def content_type_for_static_asset(filename: str) -> str:
    return _STATIC_CONTENT_TYPES[filename]
