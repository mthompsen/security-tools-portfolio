"""Shared pytest fixtures and path setup for log_parser tests."""

import sys
from pathlib import Path

# Add the parent directory (log-parser/) to sys.path so we can import log_parser
sys.path.insert(0, str(Path(__file__).parent.parent))
