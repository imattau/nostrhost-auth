from __future__ import annotations

import pytest

from nostrhost_auth.identity.mappings import MappingStore


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "identities.db")
