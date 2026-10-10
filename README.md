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

Check which version you have with `chatui --version`.

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
| `c` | call the open chat, or join the call going on in a group (`m` mutes, `x` hangs up) |
| `v` | invite someone new (`c` copies a message to send them) |
| `g` / `+` / `e` | new group / add people to the open group / rename it |
| `@name` | mention someone (Tab completes) |
| `↑↓` then `r` | in the message pane: pick a message and reply to it |
| `i` | safety number to compare in person (`m` marks it verified), group members |
| `t` or Ctrl-T | pick a theme: default, dracula, gruvbox, nord, solarized, synthwave, or your own |
| `?` | everything else |

Type these in the message box:

| Command | |
| --- | --- |
| `/accept <name>` | accept a friend's new key, after comparing safety numbers (`i`) |
| `/remove <name>` | group admin: take someone out of the open group |
| `/grant <name>` / `/revoke <name>` | group admin: let a member remove people, or take that back |
| `/handover <name>` | group admin: pass the admin role to a member, then you can leave |
| `/claim` | take over a group that has no admin (made before admins existed) |
| `/leave` | leave the open group (the admin hands over first) |
| `/receipts on` / `off` | show or hide read receipts |
| `/notify on` / `off` | desktop notifications for new messages (Linux, macOS, Windows) |
| `/notify hide` / `show` | notifications say only "New message", or show who and what |
| `/tutorial` / `/help` | the first-run tour again / every key |

Whoever makes a group is its admin. Only the admin, or a member the admin has
granted, can `/remove` people; anyone can `/leave`, except the admin, who
hands the role over with `/handover` first. A group made before admins existed
has none: the first member to `/claim` it becomes admin. The admin signs the
list of who may remove people, so members can check it and a helper's removal
works even if someone missed the grant. Everyone in a group needs 0.9.8 or newer
for the group rules, and the newest version for the signed list; older ones keep
working, just without the check.

## Back up your account

`chatui backup <file>` saves your account to one encrypted file, and
`chatui restore <file>` puts it back on a device (`--force` replaces the account
already there). Chats are not included, and a backup still needs your passphrase.

## Calls

Press `c` in a chat to call. It works for one-to-one chats and for groups of up to
8 people. In a group, everyone gets a note that a call has started, and joins with
`c`. Once you're connected, everyone sees the same **four emoji**. Read them out to
each other: if they match, nobody else can listen in. Like Telegram's, they come
from a key made fresh for every call, which a listener in the middle can't fake
without the emoji coming out different.

Voice is sent with Opus over UDP, encrypted end to end. It goes straight to the
other person when both of your networks allow it, and through the relay when they
don't. Going straight means the other person learns your IP address. To avoid
that, press `r` in the call window: voice then always goes through the relay. On
macOS your terminal asks for the microphone the first time; on Linux you need
ALSA (or PipeWire/PulseAudio with ALSA support), which the .deb installs.

## Themes, made by AI

`chatui mcp` is an [MCP](https://modelcontextprotocol.io) server that lets an
assistant design color themes. With Claude Code:

```sh
claude mcp add chatui -- chatui mcp
```

Then ask for "a synthwave theme for chatui". A running chatui switches to it
within a second. Themes are plain JSON in `~/.chatui/themes`.

## Run the tests

```sh
cargo test
```

No server needs to be running: the tests start their own relay on a free local port.
See [SECURITY.md](SECURITY.md) for what chatui protects and what it doesn't.

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

**Calls** use UDP on the same port as the relay (6769 by default), for people
whose networks won't let them reach each other directly. A Cloudflare Tunnel
can't carry UDP, so open that port on the relay's machine and tell the relay
where clients can reach it: `chatui serve --udp calls.example.com:6769`, a name
that points straight at the machine, not through the tunnel. Without that, calls
still work whenever both people can reach each other directly. The relay only
passes along encrypted voice, caps each person at about 96 KB/s, and never sends
anything to an address that didn't first prove it belongs to a logged-in person.

The relay speaks plain WebSocket, and clients only connect to it over TLS (wss),
so put it behind something that terminates TLS with a real certificate, such as
a Cloudflare Tunnel. `chat.example.com` connects on 443, `chat.example.com:8443`
on that port. Unencrypted `ws://` works only for `localhost`, so the network
can't see who talks to whom or hand out fake keys.

Each address can have only a few logins in progress at once, so one machine
can't keep everyone else out. Through a proxy on the same machine every
connection looks like `127.0.0.1`, so the relay goes by the `CF-Connecting-IP`
header a Cloudflare Tunnel adds (or `X-Forwarded-For`). Behind a proxy that
sets neither, only the overall limit applies.

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
- **Calls** are end-to-end encrypted too. Call setup goes through the same Olm
  sessions as messages. Each call agrees fresh X25519 keys by commit-then-reveal,
  and everyone compares 4 emoji made from them. Every voice packet is sealed with
  ChaCha20-Poly1305 under a key only its sender and receiver have, and replays
  are dropped.
- **The relay** never holds keys that can read messages. It keeps undelivered
  messages, encrypted, until they're picked up, and keeps nothing after that.
  It only takes TLS from anywhere but `localhost`.

What it doesn't hide: the relay sees who messages whom and when, and how big the
messages are; for calls, who calls whom and for how long. A direct call shows
each person's IP address to the others (`r` in a call turns that off). Each account lives on one device. chatui's own code hasn't been
independently audited; the cryptography comes from libraries that have.
Upgrading from before 0.9: everyone in a chat needs the new version; older
clients are told to update rather than silently dropped.

## Contributing

Pull requests are checked automatically (formatting, tests on Linux and macOS, a
Windows build). Every change merged into `main` is released by itself: the
version goes up, and apt, Homebrew and the Windows download follow within
minutes. To release a bigger version, bump it in `Cargo.toml` in the PR.
