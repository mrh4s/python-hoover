"""Common fixtures for the Hoover test suite."""

import os
import sys
import tempfile
import pytest

# Ensure the project root is on sys.path so that imports like
# ``from utils import ...`` work inside tests the same way they
# work from the project root.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture
def tmp_dir(tmp_path):
    """Return a temporary directory (pathlib.Path) that is cleaned up after the test."""
    return tmp_path


@pytest.fixture
def sample_ssid_file(tmp_path):
    """Create a sample SSID text file and return its path."""
    ssid_file = tmp_path / "ssids.txt"
    ssid_file.write_text(
        "# This is a comment\n"
        "CoffeeShop-WiFi\n"
        "\n"
        "Hotel-Guest\n"
        "# Another comment\n"
        "Airport-Free-WiFi\n"
        "\n"
    )
    return str(ssid_file)


@pytest.fixture
def empty_ssid_file(tmp_path):
    """Create an empty SSID text file and return its path."""
    ssid_file = tmp_path / "empty.txt"
    ssid_file.write_text("")
    return str(ssid_file)


@pytest.fixture
def comments_only_ssid_file(tmp_path):
    """Create an SSID file containing only comments and blank lines."""
    ssid_file = tmp_path / "comments.txt"
    ssid_file.write_text("# comment 1\n# comment 2\n\n\n")
    return str(ssid_file)


@pytest.fixture
def mock_interface():
    """Return a safe, fake interface name for testing."""
    return "wlan0mon"
