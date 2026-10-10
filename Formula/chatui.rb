class Chatui < Formula
  desc "Tiny end-to-end encrypted terminal chat for you and your friends"
  homepage "https://github.com/CozminRebeja/chatui"
  url "https://github.com/CozminRebeja/chatui/archive/refs/tags/v0.9.14.tar.gz"
  sha256 "4a8f38a70492a6ae62fa8f05963b6d6cb176372db330ac719e581b13ddc928ef"
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
