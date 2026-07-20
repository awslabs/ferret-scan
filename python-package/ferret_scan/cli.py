# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
CLI wrapper for ferret-scan binary
"""

import hashlib
import platform
import stat
import subprocess
import sys
from pathlib import Path

import requests


class FerretScanCLI:
    """Wrapper for ferret-scan binary with automatic download"""

    GITHUB_RELEASES_URL = "https://api.github.com/repos/awslabs/ferret-scan/releases/latest"

    def __init__(self):
        self.binary_dir = Path(__file__).parent / "binaries"
        self.binary_dir.mkdir(exist_ok=True)

    def get_platform_info(self):
        """Get platform and architecture information"""
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Map platform names
        if system == "darwin":
            system = "darwin"
        elif system == "linux":
            system = "linux"
        elif system == "windows":
            system = "windows"
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        # Map architecture names
        if machine in ["x86_64", "amd64"]:
            arch = "amd64"
        elif machine in ["aarch64", "arm64"]:
            arch = "arm64"
        else:
            raise RuntimeError(f"Unsupported architecture: {machine}")

        return system, arch

    def get_binary_name(self):
        """Get the expected binary name for this platform"""
        system, arch = self.get_platform_info()

        if system == "windows":
            return f"ferret-scan-{system}-{arch}.exe"
        else:
            return f"ferret-scan-{system}-{arch}"

    def get_binary_path(self):
        """Get the path to the binary for this platform"""
        binary_name = self.get_binary_name()
        return self.binary_dir / binary_name

    def download_binary(self):
        """Download the appropriate binary for this platform"""
        system, arch = self.get_platform_info()
        binary_path = self.get_binary_path()

        if binary_path.exists():
            return binary_path

        print(f"Downloading ferret-scan binary for {system}-{arch}...", file=sys.stderr)

        try:
            # Get latest release info
            try:
                response = requests.get(self.GITHUB_RELEASES_URL, timeout=30)
                response.raise_for_status()
            except requests.exceptions.Timeout:
                raise RuntimeError(
                    "Network timeout while fetching release information. "
                    "Please check your internet connection and try again."
                )
            except requests.exceptions.ConnectionError:
                raise RuntimeError(
                    "Unable to connect to GitHub to fetch release information. "
                    "Please check your internet connection and firewall settings."
                )
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    raise RuntimeError(
                        "GitHub API rate limit exceeded. Please try again later or "
                        "download the binary manually from the releases page."
                    )
                else:
                    raise RuntimeError(
                        f"Failed to fetch release information from GitHub (HTTP {e.response.status_code}). "
                        "Please try again later."
                    )

            try:
                release_data = response.json()
            except ValueError as e:
                raise RuntimeError(
                    "Invalid response from GitHub API. Please try again later."
                )

            # Find the appropriate asset
            system, arch = self.get_platform_info()
            download_url = None
            download_name = None
            checksums_url = None

            for asset in release_data.get("assets", []):
                asset_name = asset["name"]

                # Capture the checksums manifest so the downloaded binary can be
                # integrity-verified before we chmod +x and execute it (MED-5).
                if asset_name in ("checksums.txt", "ferret-scan_checksums.txt") or (
                    asset_name.startswith("ferret-scan") and asset_name.endswith("checksums.txt")
                ):
                    checksums_url = asset["browser_download_url"]
                    continue

                # Check if this asset matches our platform
                # Support both formats: ferret-scan-darwin-arm64 and ferret-scan_1.2.2_darwin_arm64
                if (system in asset_name and arch in asset_name and
                    asset_name.startswith("ferret-scan") and
                    not asset_name.endswith((".whl", ".tar.gz", ".txt", ".md"))):

                    # Additional validation for Windows executables
                    if system == "windows" and not asset_name.endswith(".exe"):
                        continue
                    elif system != "windows" and asset_name.endswith(".exe"):
                        continue

                    download_url = asset["browser_download_url"]
                    download_name = asset_name
                    break

            if not download_url:
                available_assets = [asset["name"] for asset in release_data.get("assets", [])]
                raise RuntimeError(
                    f"Binary not found for {system}-{arch}. "
                    f"Available assets: {', '.join(available_assets) if available_assets else 'none'}. "
                    "Please check if your platform is supported or download manually."
                )

            # Download the binary
            try:
                print(f"Downloading from {download_url}...", file=sys.stderr)
                response = requests.get(download_url, timeout=300)
                response.raise_for_status()
            except requests.exceptions.Timeout:
                raise RuntimeError(
                    "Network timeout while downloading binary. "
                    "The file may be large - please check your connection and try again."
                )
            except requests.exceptions.ConnectionError:
                raise RuntimeError(
                    "Connection lost while downloading binary. "
                    "Please check your internet connection and try again."
                )
            except requests.exceptions.HTTPError as e:
                raise RuntimeError(
                    f"Failed to download binary (HTTP {e.response.status_code}). "
                    "Please try again later or download manually."
                )

            # Verify the download's SHA-256 against the release's checksums.txt
            # BEFORE writing an executable bit or running it (MED-5). Without this
            # a tampered asset would be chmod +x'd and executed unconditionally.
            # HTTPS protects transport; this additionally detects a corrupted or
            # substituted asset. The manifest is fetched from the SAME release.
            self._verify_checksum(response.content, download_name, checksums_url)

            # Write binary to disk
            try:
                with open(binary_path, "wb") as f:
                    f.write(response.content)

                # Make executable
                binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC)
            except OSError as e:
                raise RuntimeError(
                    f"Failed to write binary to {binary_path}: {e}. "
                    "Please check file permissions and available disk space."
                )

            print(f"Successfully downloaded ferret-scan binary to {binary_path}", file=sys.stderr)
            return binary_path

        except RuntimeError:
            # Re-raise RuntimeError with our custom messages
            raise
        except Exception as e:
            # Catch any other unexpected errors
            raise RuntimeError(
                f"Unexpected error while downloading ferret-scan binary: {e}. "
                "Please try downloading the binary manually from the GitHub releases page."
            )

    def _verify_checksum(self, content, asset_name, checksums_url):
        """Verify the downloaded binary's SHA-256 against the release's
        checksums.txt manifest before it is made executable (MED-5).

        The manifest is goreleaser's standard format: one "  " line per
        asset. We locate the line for our asset_name and compare its
        digest to the SHA-256 of the downloaded bytes. Any mismatch,
        missing manifest, or missing entry is a hard failure — we never
        execute an unverified binary.
        """
        if not checksums_url:
            raise RuntimeError(
                "Release is missing a checksums.txt manifest; refusing to run an "
                "unverified binary. Please download and verify manually."
            )
        if not asset_name:
            raise RuntimeError(
                "Internal error: downloaded asset name unknown; cannot verify checksum."
            )

        try:
            resp = requests.get(checksums_url, timeout=60)
            resp.raise_for_status()
            manifest = resp.text
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"Failed to fetch checksums manifest for integrity verification: {e}."
            )

        expected = None
        for line in manifest.splitlines():
            parts = line.split()
            # goreleaser format: "<sha256>  <filename>"
            if len(parts) == 2 and parts[1] == asset_name:
                expected = parts[0].lower()
                break

        if not expected:
            raise RuntimeError(
                f"No checksum entry for {asset_name} in the release manifest; "
                "refusing to run an unverified binary."
            )

        actual = hashlib.sha256(content).hexdigest().lower()
        if actual != expected:
            raise RuntimeError(
                f"Checksum mismatch for {asset_name}: expected {expected}, got {actual}. "
                "The download may be corrupted or tampered with; refusing to run it."
            )
        print(f"Verified SHA-256 for {asset_name}", file=sys.stderr)

    def run(self, args):
        """Run ferret-scan with the given arguments"""
        try:
            binary_path = self.download_binary()
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            print("\nTroubleshooting tips:", file=sys.stderr)
            print("1. Check your internet connection", file=sys.stderr)
            print("2. Verify firewall settings allow GitHub access", file=sys.stderr)
            print("3. Download binary manually from: https://github.com/awslabs/ferret-scan/releases", file=sys.stderr)
            return 2  # Error exit code

        # Execute the binary with all arguments
        try:
            result = subprocess.run([str(binary_path)] + args, stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)
            return result.returncode
        except KeyboardInterrupt:
            return 130  # Standard exit code for Ctrl+C
        except FileNotFoundError:
            print(f"Error: Binary not found at {binary_path}. Please try reinstalling the package.", file=sys.stderr)
            return 2
        except PermissionError:
            print(f"Error: Permission denied executing {binary_path}. Please check file permissions.", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Error running ferret-scan: {e}", file=sys.stderr)
            print("Please report this issue at: https://github.com/awslabs/ferret-scan/issues", file=sys.stderr)
            return 2


def main():
    """Main entry point for the CLI"""
    cli = FerretScanCLI()
    exit_code = cli.run(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
