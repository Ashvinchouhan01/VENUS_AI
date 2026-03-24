#!/usr/bin/env python3
"""
venus_cli.py – Entry-point wrapper for VENUS_AI.

Usage
-----
    python venus_cli.py interactive
    python venus_cli.py scenario basic-web --target https://example.com
    python venus_cli.py report --target https://example.com
"""

import sys
import os

# Ensure the venus_ai package directory is on the path when this script is
# invoked from outside it (e.g. as a system-wide symlink).
sys.path.insert(0, os.path.dirname(__file__))

from cli import main

if __name__ == "__main__":
    main()
