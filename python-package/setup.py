# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3

import os

from setuptools import find_packages, setup

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ferret-scan",
    use_scm_version={
        "root": "..",
        "relative_to": __file__,
    },
    setup_requires=["setuptools_scm"],
    author="AWS",
    author_email="ferret-scan@amazon.com",
    description="Sensitive data detection tool with pre-commit hook support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/awslabs/ferret-scan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "ferret-scan=ferret_scan.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ferret_scan": ["binaries/*"],
    },
)
