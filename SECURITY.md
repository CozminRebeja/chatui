# Security

chatui encrypts your messages end to end. The relay only passes along ciphertext.

## What it protects

- **Message contents**: sealed with Olm (double ratchet), so past messages stay
  unreadable even if a key is stolen later.
- **Your key and history on disk**: encrypted with your passphrase (Argon2id,
  XSalsa20-Poly1305). Choose one of at least 8 characters, and remember it: without
  it the account on that device can't be recovered.
- **Calls**: set up over the same Olm sessions, with fresh X25519 keys for every
  call (and again whenever someone joins), exchanged by commit-then-reveal so
  nobody in the middle can choose a key that makes the emoji match. Compare the
  4 emoji (about 32 bits) out loud: if they match, nobody else is listening.
  Voice packets are sealed with ChaCha20-Poly1305 per sender and receiver,
  counter nonces, a replay window; anything that doesn't authenticate is dropped
  without a reply.
- **Who you're talking to**: safety numbers, which you should compare in person or
  over another app (`i` in a chat). Invite codes pin the inviter's key.

## What it doesn't protect

- **Metadata.** The relay sees who talks to whom, when, and how much, including
  who calls whom and for how long.
- **Your IP address in a direct call.** The other people in the call see it.
  Press `r` in a call to always go through the relay instead.
- **Call setup tokens on the network.** The token that lets your client use the
  relay's UDP side travels in the clear (the voice doesn't). Someone who can
  watch your traffic could use it to disrupt that call, never to hear it.
- **A compromised device.** Anyone who can run chatui as you, with your passphrase,
  can read your chats.
- **Unverified contacts.** Until you compare safety numbers, a relay could
  substitute keys for a first contact.
- **Group admin rules only go as far as the admin's signature.** The admin signs
  who may remove people (a roster, with a key derived from their chatui key, so
  it survives a backup restore), and a helper's removal carries that proof. But
  a member only checks a signature against a key the admin sent them directly.
  Someone invited by another member takes that member's word on who the admin
  is until the real admin's next signed roster arrives; if they already know the
  real admin's key, an invite naming them without their signature is refused,
  and a roster signed by someone else claiming to be admin is flagged, not
  believed. A group whose admin runs an older chatui has no signatures and
  works as before. Groups made before admins existed have none until a member
  runs `/claim`. Whoever claims first wins, but if two members claim at the
  same moment they can end up with different admins.
- **Notifications on screen.** `/notify` shows the sender and the first 100
  characters of a message on your desktop, where anyone looking at the screen
  can see them. `/notify hide` shows only "New message" instead.

## Reporting a problem

Please report security problems privately to the maintainer before opening a public
issue, so a fix can ship first.
