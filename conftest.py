"""
conftest.py — pytest configuration for SENTINELAUDIT.

Adds the project root to sys.path so that all test files can import
core, platforms, rules, and report packages without installing the project.
"""

import sys
import os

# Ensure the sentinelaudit project root is on the path
sys.path.insert(0, os.path.dirname(__file__))
