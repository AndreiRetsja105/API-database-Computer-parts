// FILE: /README-secure-features.md
# Secure Features: Password Manager, Secure Storage, Sign/Verify


## Algorithms & Parameters
- **KDF:** PBKDF2-HMAC-SHA-256, 150k iterations, 128-bit salt.
- **Symmetric Crypto:** AES-GCM-256 with 96-bit random IV (nonce).
- **Integrity:** GCM tag; plus **HMAC-SHA-256** over metadata for .secure packages (key separation).
- **Signatures:** ECDSA (P-256) with SHA-256; keys exported as SPKI (public) and PKCS#8 (private).


## Threat Model (short)
- Lost device: vault/file blobs remain confidential (AES-GCM, KDF).
- Tampering: GCM tag + HMAC detects changes.
- IV reuse risk: avoided via `crypto.getRandomValues(12)`. Never reuse IV per key.
- Weak passwords: mitigated via KDF; recommend long passphrases.


## How to wire into your app
1. Copy `/js/crypto-utils.js`, `password-manager.html`, `secure-storage.html`, `sign-verify.html`.
2. Ensure `<script type="module">` works; serve over HTTP(s) or `live-server`.
3. Link from your navbar (already included in each page).
4. Keep your global CSS; minimal classes used here.


## Demo script (5 minutes)
1. **Password Manager:** register → login → add entry → lock → show localStorage encrypted blob.
2. **Secure Storage:** choose a file → encrypt → download `.secure` → re-import with password → file restores.
3. **Sign/Verify:** generate keys → sign a file → verify with exported public key; show success/failure.