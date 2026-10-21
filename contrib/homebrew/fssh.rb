# Homebrew formula for fssh. Builds from source, so the binary is not
# quarantined by Gatekeeper even though it is not signed by Apple.
#
# Publish it in a tap repository named "homebrew-fssh":
#   brew tap Mister-leo/fssh
#   brew install fssh            # latest release
#   brew install --HEAD fssh     # current main branch
#
# On each release, update `url` to the new tag and `sha256` to:
#   curl -sL https://github.com/Mister-leo/fssh/archive/refs/tags/<tag>.tar.gz | shasum -a 256
class Fssh < Formula
  desc "SSH key manager and agent unlocked by Touch ID or OTP"
  homepage "https://github.com/Mister-leo/fssh"
  url "https://github.com/Mister-leo/fssh/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_TARBALL_SHA256"
  head "https://github.com/Mister-leo/fssh.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    # Touch ID and Keychain bindings need cgo
    ENV["CGO_ENABLED"] = "1"
    ldflags = "-s -w -X main.version=#{version}"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/fssh"
  end

  def caveats
    <<~EOS
      Run the setup wizard to create the master key, import keys and start
      the agent at login:
        fssh init
    EOS
  end

  test do
    assert_match "fssh", shell_output("#{bin}/fssh version")
  end
end
