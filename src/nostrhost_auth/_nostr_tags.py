"""Shared tag-extraction helper for already-parsed `nostr_sdk.Event` objects.

Both `auth/nostr_verify.py` (single-value tags like `domain`/`action`) and
`identity/relays.py` (`r` tags, which also carry an optional read/write
marker as a third element) need to walk `event.tags()` looking for tags
with a given name; this is the one place that loop is written.
"""

from __future__ import annotations

from collections.abc import Iterator

from nostr_sdk import Event


def tags_named(event: Event, name: str) -> Iterator[list[str]]:
    """Yield each tag's full value list (`tag.to_vec()`) named `name`.

    A tag with fewer than two elements has no name/value pair worth
    matching and is skipped.
    """
    for tag in event.tags():
        values = tag.to_vec()
        if len(values) >= 2 and values[0] == name:
            yield values
