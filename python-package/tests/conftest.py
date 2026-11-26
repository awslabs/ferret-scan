# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

# Import ferret_scan from the source tree, not from an installed wheel.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
