import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

_ports = itertools.count(47900)


@pytest.fixture
def port_pair():
    """Two fresh loopback UDP ports: (simulator, scanner)."""
    return next(_ports), next(_ports)
