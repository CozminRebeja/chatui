# chatui

Tiny end-to-end encrypted terminal chat for you and your friends.

Keys are made on your device and never leave it; the relay server only ever
passes along ciphertext. Every message has its own key, deleted once used
(a double ratchet, via the audited [vodozemac](https://github.com/matrix-org/vodozemac)),
so even someone who steals your key later can't read what they recorded before.
It's invite only: someone already on chatui gives you a code.

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

Updates come with `sudo apt upgrade`. Before trusting the key, check its
fingerprint: `gpg --show-keys /etc/apt/keyrings/chatui.gpg` must print
`49DF 73CD 441A 24C4 55DE  625A AF41 2E0A 69CC 965F`.

**Windows**

Download [chatui.exe](https://github.com/CozminRebeja/chatui/releases/latest/download/chatui.exe)
and run it from Windows Terminal. It isn't code-signed, so SmartScreen may ask:
choose *More info → Run anyway*. To check it's the real thing, compare its
SHA-256 (`certutil -hashfile chatui.exe SHA256`) with the line in the release's
`SHA256SUMS`, whose signature (`SHA256SUMS.asc`) is made with the apt key above.

## Get started

Run `chatui` and choose a passphrase: your key and messages are encrypted with
it on your device, and you type it each time chatui starts. There's no reset;
forget it and that account is gone. Then pick a username and paste the invite
code a friend sent you. Whoever invited you shows up as your first chat,
already verified: the code carries a fingerprint of their key, so not even the
relay can slip in a fake one.

Everyone else starts out *not verified*. Press `i` in a chat to see your safety
number, compare it with your friend in person or on a call, and if it matches
press `m`. Then nobody, including whoever runs the relay, can read or fake your
messages. If someone adds you to a group, you join it with `y` or decline with `d`.

| Key | |
| --- | --- |
| `f` | add a friend by username |
| `v` | invite someone new (`c` copies a message to send them) |
| `g` / `+` / `e` | new group / add people to the open group / rename it |
| `@name` | mention someone (Tab completes) |
| `↑↓` then `r` | in the message pane: pick a message and reply to it |
| `i` | safety number to compare in person (`m` marks it verified), group members |
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

The first account on a new relay needs no invite; that's you, and you're its
admin. Everyone after gets in with a code from someone who's already there.
Each person can have 3 unused invites at a time, and new accounts can invite
after a day, so one leaked code can't snowball. The admin presses `B` to remove
someone: they're logged out, can't log back in or be messaged, and their unused
invites stop working. A relay from before 0.9 has no admin yet: run
`chatui serve --admin <your username>` once.

Someone forgot their passphrase? With the relay stopped, `chatui serve --release <name>`
frees their username and `chatui serve --invite` prints a code to sign up with again.

The relay speaks plain WebSocket, and clients only connect to it over TLS (wss),
so put it behind something that terminates TLS with a real certificate, such as
a Cloudflare Tunnel. `chat.example.com` connects on 443, `chat.example.com:8443`
on that port. Unencrypted `ws://` works only for `localhost`, so the network
can't see who talks to whom or hand out fake keys.

## Security

- **End-to-end encrypted, with forward secrecy.** Each pair of people shares an
  Olm session (a Signal-style double ratchet), started from a one-time prekey
  the relay hands out once. Groups send each member their own copy through
  those sessions. Your Olm identity key is your chatui key, so safety numbers
  cover it.
- **Verified contacts.** Safety numbers are 60 digits; invite codes carry a
  fingerprint of the inviter's key. A changed key is refused, never accepted
  quietly.
- **Encrypted on disk** with your passphrase (Argon2id, XSalsa20-Poly1305), and
  any tampering with the files is caught.
- **The relay** never holds keys that can read messages. It keeps undelivered
  messages, encrypted, until they're picked up, and keeps nothing after that.
  It only takes TLS from anywhere but `localhost`.

What it doesn't hide: the relay sees who messages whom and when, and how big the
messages are. Each account lives on one device. chatui's own code hasn't been
independently audited; the cryptography comes from libraries that have.
Upgrading from before 0.9: everyone in a chat needs the new version; older
clients are told to update rather than silently dropped.
