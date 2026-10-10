class Chatui < Formula
  desc "Tiny end-to-end encrypted terminal chat for you and your friends"
  homepage "https://github.com/CozminRebeja/chatui"
  url "https://github.com/CozminRebeja/chatui/archive/refs/tags/v0.9.9.tar.gz"
  sha256 "d6932d52719b6fa02fbd3b0ead69ccbd44cef33f01db7067cb6cf4c6efd16eeb"
  head "https://github.com/CozminRebeja/chatui.git", branch: "main"

  depends_on "rust" => :build

  def install
    # prefilled on the first-run screen; anyone can change it there
    ENV["CHATUI_SERVER"] = "chat.rebeja.co"
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
