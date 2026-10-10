class Chatui < Formula
  desc "Tiny end-to-end encrypted terminal chat for you and your friends"
  homepage "https://github.com/CozminRebeja/chatui"
  url "https://github.com/CozminRebeja/chatui/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "531ddc6317f2201bfae3c4895a41511013ab5078040e557a13b0f25cacadd494"
  head "https://github.com/CozminRebeja/chatui.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  # whoever hosts the relay: `brew services start chatui`
  service do
    run [opt_bin/"chatui", "serve"]
    keep_alive true
    log_path var/"log/chatui.log"
    error_log_path var/"log/chatui.log"
  end

  test do
    assert_match "usage", shell_output("#{bin}/chatui bogus 2>&1", 1)
  end
end
