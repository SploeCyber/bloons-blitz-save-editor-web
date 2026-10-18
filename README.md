# Blitz Save Lab

Client-side web version of the Bloons Blitz `Profile.Save` editor. It follows the container flow in the reference project by MrNukeAlt:

- PBKDF2-HMAC-SHA1 with 10 iterations and app ID/password `26`
- AES-128-CBC with PKCS#7 padding
- zlib compression
- original Ninja Kiwi header metadata preserved on export
- save counter incremented and a new 24-byte salt generated for every export
- generated save decrypted and compared with the exact intended payload before download

## Modes

**Prepared fields** provides the sections from the desktop editor: general and currencies, metadata, monkeys, heroes and gear, inventory, missions and FTUE, map progress, upgrades and stickers, loot and rewards, and trading/stats.

**Raw edit** exposes the complete decrypted payload. Unknown or newly added game fields remain available here even when they are not represented by a prepared field.

## Privacy and safety

The app has no server endpoint and does not upload the selected file. Decryption, editing, encryption, and verification happen in the browser. The original file is never overwritten; the browser downloads a new `<name>_edited.Save` file.

This is an unofficial tool. Keep an untouched backup and test exported saves with a disposable copy of your profile.

## GitHub Pages

The included workflow publishes the repository with GitHub Pages whenever `main` changes.

1. Create a public GitHub repository and push this directory to its `main` branch.
2. In **Settings -> Pages**, select **GitHub Actions** as the source if GitHub has not selected it automatically.
3. Wait for the `Deploy to GitHub Pages` workflow to finish.

The site is static and has no build step. Third-party browser libraries are vendored in `src/` so the editor also works when the CDN is unavailable.

## Local preview

```bash
python3 -m http.server 4173
```

Open <http://localhost:4173>.

## Attribution

Reference implementation: <https://github.com/MrNukeAlt/Bloons-Blitz-Save-Editor>. This web interface is an independent browser implementation of the documented format, not a copy of the desktop GUI.