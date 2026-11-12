#!/usr/bin/env python3
"""Investigator CLI launcher."""
import sys
import os

# Ensure package root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from investigator.cli import main

if __name__ == "__main__":
    main()

