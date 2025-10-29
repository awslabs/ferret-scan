# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Ferret Scan - Sensitive Data Detection Tool

A Python wrapper for the Ferret Scan Go binary that provides
easy installation and pre-commit hook integration.
"""

try:
    from importlib.metadata import version
    __version__ = version("ferret-scan")
except ImportError:
    # Fallback for older Python versions or development
    try:
        import pkg_resources
        __version__ = pkg_resources.get_distribution("ferret-scan").version
    except Exception:
        __version__ = "unknown"

__author__ = "AWS"
