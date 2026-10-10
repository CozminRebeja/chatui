# chatui

Tiny end-to-end encrypted terminal chat for you and your friends.

Keys are made on your device and never leave it; the relay server only ever
passes along ciphertext. It's invite only: someone already on chatui gives you
a code.

## Install

**macOS** (Homebrew, also works on Linux)

```sh
brew tap CozminRebeja/chatui https://github.com/CozminRebeja/chatui
brew install chatui
```

**Debian / Ubuntu** (apt)

```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://cozminrebeja.github.io/chatui/chatui.gpg | sudo tee /etc/apt/keyrings/chatui.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/chatui.gpg] https://cozminrebeja.github.io/chatui ./" | sudo tee /etc/apt/sources.list.d/chatui.list
sudo apt update && sudo apt install chatui
```

Updates come with `sudo apt upgrade`.

**Windows**

Download [chatui.exe](https://github.com/CozminRebeja/chatui/releases/latest/download/chatui.exe)
and run it from Windows Terminal. It isn't code-signed, so SmartScreen may ask:
choose *More info → Run anyway*.

## Get started

Run `chatui`, pick a username, and paste the invite code a friend sent you.
Whoever invited you shows up as your first chat.

| Key | |
| --- | --- |
| `f` | add a friend by username |
| `v` | invite someone new (`c` copies a message to send them) |
| `g` / `+` / `e` | new group / add people to the open group / rename it |
| `@name` | mention someone (Tab completes) |
| `↑↓` then `r` | in the message pane: pick a message and reply to it |
| `i` | members and key fingerprints, to compare in person |
| `t` or Ctrl-T | pick a theme: default, dracula, gruvbox, nord, solarized, synthwave, or your own |
| `?` | everything else |

## Themes, made by AI

`chatui mcp` is an [MCP](https://modelcontextprotocol.io) server that lets an
assistant design color themes. With Claude Code:

```sh
claude mcp add chatui -- chatui mcp
```

Then ask for "a synthwave theme for chatui". A running chatui switches to it
within a second. Themes are plain JSON in `~/.chatui/themes`.

## Run your own relay

```sh
chatui serve            # listens on [::]:6769
brew services start chatui
```

The first account on a new relay needs no invite; that's you. Everyone after
gets in with a code from someone who's already there. Friends on the same
network connect with `yourmachine.local:6769`; a bare domain like
`chat.example.com` connects over wss on 443 (e.g. through a Cloudflare Tunnel).
