"""Shared pytest fixtures and path setup for password_checker tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
