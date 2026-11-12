"""Close every database engine the relying party creates once its test ends.

Each test builds its own app and engine. Left open, their connection pools
accumulate until PostgreSQL refuses new clients (max_connections).
"""

from unittest.mock import patch

import pytest

from quantumkey.server import service


@pytest.fixture(autouse=True)
def _dispose_relying_party_engines():
    engines = []
    real = service.create_engine

    def tracking(*args, **kwargs):
        engine = real(*args, **kwargs)
        engines.append(engine)
        return engine

    with patch.object(service, "create_engine", tracking):
        yield
    for engine in engines:
        engine.dispose()
