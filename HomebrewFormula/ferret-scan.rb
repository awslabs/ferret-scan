# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

class FerretScan < Formula
  desc "Find and redact sensitive data before it leaks — PII, secrets, credit cards, metadata"
  homepage "https://github.com/awslabs/ferret-scan"
  version "2.0.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/awslabs/ferret-scan/releases/download/v#{version}/ferret-scan_#{version}_darwin_arm64"
      sha256 "b1fe68f551cdd305f83089ed35569d58a7a07c1df17656fa3762066977905e76"
    else
      url "https://github.com/awslabs/ferret-scan/releases/download/v#{version}/ferret-scan_#{version}_darwin_amd64"
      sha256 "a4e0aeda37a898f53bb874b422f31f0af5302171a2e065b8e0a4a27f2e5fc2b2"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/awslabs/ferret-scan/releases/download/v#{version}/ferret-scan_#{version}_linux_arm64"
      sha256 ""  # populated by goreleaser on release
    else
      url "https://github.com/awslabs/ferret-scan/releases/download/v#{version}/ferret-scan_#{version}_linux_amd64"
      sha256 ""  # populated by goreleaser on release
    end
  end

  def install
    # The download IS the precompiled binary — just install it directly.
    binary_name = Dir["ferret-scan*"].first || "ferret-scan"
    bin.install binary_name => "ferret-scan"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ferret-scan --version")

    (testpath / "test.txt").write "card 5500-0000-0000-0004\n"
    output = shell_output("#{bin}/ferret-scan --file #{testpath}/test.txt 2>&1")
    assert_match "creditcard", output
  end
end
