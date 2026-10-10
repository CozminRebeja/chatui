# Security

chatui encrypts your messages end to end. The relay only passes along ciphertext.

## What it protects

- **Message contents**: sealed with Olm (double ratchet), so past messages stay
  unreadable even if a key is stolen later.
- **Your key and history on disk**: encrypted with your passphrase (Argon2id,
  XSalsa20-Poly1305). Choose one of at least 8 characters, and remember it: without
  it the account on that device can't be recovered.
- **Who you're talking to**: safety numbers, which you should compare in person or
  over another app (`i` in a chat). Invite codes pin the inviter's key.

## What it doesn't protect

- **Metadata.** The relay sees who talks to whom, when, and how much.
- **A compromised device.** Anyone who can run chatui as you, with your passphrase,
  can read your chats.
- **Unverified contacts.** Until you compare safety numbers, a relay could
  substitute keys for a first contact.
- **Group admin rules are enforced by each member's app.** They aren't backed by
  signed group records. A member who hasn't yet received a grant may ignore a
  removal, and an invitee takes the admin's name from the person who invited
  them, so a malicious member could claim a false admin. Groups made before
  admins existed have none until a member runs `/claim`. Whoever claims first
  wins, but if two members claim at the same moment they can end up with
  different admins. A handover is trusted just as far as the current admin's app.
- **Notifications on screen.** `/notify` shows the sender and the first 100
  characters of a message on your desktop, where anyone looking at the screen
  can see them. `/notify hide` shows only "New message" instead.

## Reporting a problem

Please report security problems privately to the maintainer before opening a public
issue, so a fix can ship first.
