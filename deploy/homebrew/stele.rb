# Homebrew formula for stele.
#
# Distribution strategy:
#   - Auditors / producers / operators on macOS or Linux + Homebrew
#     install the CLI + verifier tooling with `brew install`.
#   - The formula installs ONLY the binaries that make sense on a
#     workstation: stele, stele-watcher, stele-backup,
#     stele-export-chain, stele-loadgen. Server daemons (steled,
#     stele-witness, stele-mirror, stele-cosigner) ship via the
#     OCI image / Helm chart / deb / rpm where they actually run.
#
# Publishing:
#   1. Tag a release v0.1.0 — the release workflow publishes signed
#      binaries to GitHub Releases.
#   2. Copy this file into a tap repo at <owner>/homebrew-tap and
#      replace the SHA256 placeholders with the actual values from
#      the release's `hashes.txt` artifact.
#   3. Users run:
#        brew tap desledishant10/tap
#        brew install desledishant10/tap/stele
#
# The `url` lines below use `Hardware::CPU.intel?` so the formula
# auto-picks amd64 on Intel hosts and arm64 on Apple Silicon /
# linuxbrew on aarch64.

class Stele < Formula
  desc "Provenance-anchored audit log: tamper-evident, signature-chained, witness-cosigned"
  homepage "https://github.com/desledishant10/stele"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-darwin-amd64"
      sha256 "REPLACE_ME_DARWIN_AMD64"

      resource "stele-watcher" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-watcher-darwin-amd64"
        sha256 "REPLACE_ME_WATCHER_DARWIN_AMD64"
      end

      resource "stele-backup" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-backup-darwin-amd64"
        sha256 "REPLACE_ME_BACKUP_DARWIN_AMD64"
      end

      resource "stele-export-chain" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-export-chain-darwin-amd64"
        sha256 "REPLACE_ME_EXPORT_CHAIN_DARWIN_AMD64"
      end

      resource "stele-loadgen" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-loadgen-darwin-amd64"
        sha256 "REPLACE_ME_LOADGEN_DARWIN_AMD64"
      end
    end

    if Hardware::CPU.arm?
      url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-darwin-arm64"
      sha256 "REPLACE_ME_DARWIN_ARM64"

      resource "stele-watcher" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-watcher-darwin-arm64"
        sha256 "REPLACE_ME_WATCHER_DARWIN_ARM64"
      end

      resource "stele-backup" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-backup-darwin-arm64"
        sha256 "REPLACE_ME_BACKUP_DARWIN_ARM64"
      end

      resource "stele-export-chain" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-export-chain-darwin-arm64"
        sha256 "REPLACE_ME_EXPORT_CHAIN_DARWIN_ARM64"
      end

      resource "stele-loadgen" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-loadgen-darwin-arm64"
        sha256 "REPLACE_ME_LOADGEN_DARWIN_ARM64"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-linux-amd64"
      sha256 "REPLACE_ME_LINUX_AMD64"

      resource "stele-watcher" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-watcher-linux-amd64"
        sha256 "REPLACE_ME_WATCHER_LINUX_AMD64"
      end

      resource "stele-backup" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-backup-linux-amd64"
        sha256 "REPLACE_ME_BACKUP_LINUX_AMD64"
      end

      resource "stele-export-chain" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-export-chain-linux-amd64"
        sha256 "REPLACE_ME_EXPORT_CHAIN_LINUX_AMD64"
      end

      resource "stele-loadgen" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-loadgen-linux-amd64"
        sha256 "REPLACE_ME_LOADGEN_LINUX_AMD64"
      end
    end

    if Hardware::CPU.arm?
      url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-linux-arm64"
      sha256 "REPLACE_ME_LINUX_ARM64"

      resource "stele-watcher" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-watcher-linux-arm64"
        sha256 "REPLACE_ME_WATCHER_LINUX_ARM64"
      end

      resource "stele-backup" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-backup-linux-arm64"
        sha256 "REPLACE_ME_BACKUP_LINUX_ARM64"
      end

      resource "stele-export-chain" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-export-chain-linux-arm64"
        sha256 "REPLACE_ME_EXPORT_CHAIN_LINUX_ARM64"
      end

      resource "stele-loadgen" do
        url "https://github.com/desledishant10/stele/releases/download/v#{version}/stele-loadgen-linux-arm64"
        sha256 "REPLACE_ME_LOADGEN_LINUX_ARM64"
      end
    end
  end

  def install
    arch_suffix = if Hardware::CPU.intel?
      OS.mac? ? "darwin-amd64" : "linux-amd64"
    else
      OS.mac? ? "darwin-arm64" : "linux-arm64"
    end

    bin.install Dir["*"].first => "stele"

    resource("stele-watcher").stage      { bin.install Dir["*"].first => "stele-watcher" }
    resource("stele-backup").stage       { bin.install Dir["*"].first => "stele-backup" }
    resource("stele-export-chain").stage { bin.install Dir["*"].first => "stele-export-chain" }
    resource("stele-loadgen").stage      { bin.install Dir["*"].first => "stele-loadgen" }
  end

  test do
    # The CLI binaries' --help is the simplest viable smoke test —
    # it confirms the binary loaded and the flag parser ran.
    %w[stele stele-watcher stele-backup stele-export-chain stele-loadgen].each do |b|
      system "#{bin}/#{b}", "--help"
    end
  end

  def caveats
    <<~EOS
      stele's binaries are installed into #{bin}.

      This formula installs the WORKSTATION tools (CLI + auditor):
        stele
        stele-watcher
        stele-backup
        stele-export-chain
        stele-loadgen

      For SERVER daemons (steled, stele-witness, stele-mirror,
      stele-cosigner), run the official OCI image or Helm chart:
        docker pull ghcr.io/desledishant10/stele:#{version}
        helm install stele oci://ghcr.io/desledishant10/charts/stele

      Verify what you just installed with cosign:
        cosign verify-blob #{bin}/stele \\
          --certificate-identity-regexp '^https://github\\.com/desledishant10/stele/' \\
          --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
          --signature https://github.com/desledishant10/stele/releases/download/v#{version}/stele-#{Hardware::CPU.intel? ? "amd64" : "arm64"}.sig \\
          --certificate https://github.com/desledishant10/stele/releases/download/v#{version}/stele-#{Hardware::CPU.intel? ? "amd64" : "arm64"}.cert
    EOS
  end
end
