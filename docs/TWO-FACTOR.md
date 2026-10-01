# Two-factor authentication, and where Strongbox uses it

## The idea

An account is protected by two **different kinds** of proof:

- **Something you know**: a password or PIN.
- **Something you have**: a phone, a hardware key, a code generator.
- **Something you are**: a fingerprint or face.

Two passwords do not count as two factors, because one phishing page steals both. The point is that stealing the
password alone is no longer enough.

## The common types, weakest to strongest

| Type | How it works | Weakness |
|---|---|---|
| **SMS code** | The site texts you a random number | SIM-swap attacks, interception, phishable |
| **Authenticator app (TOTP)** | Your phone and the site compute the same 6 digits from a shared secret and the time | Phishable (you can type the code into a fake site); the secret can be stolen if stored carelessly |
| **Push approval** | You tap "yes" on your phone | "Prompt bombing" tricks tired users into approving |
| **Security key (FIDO2 / WebAuthn)** | A device signs a challenge that is bound to the real website | You need the key; lose it and you need a spare |

## TOTP in detail (Google Authenticator, Aegis, and Strongbox's authenticator fields)

1. **Setup.** The site makes a random secret (the *seed*, typically 160 bits) and shows it as a QR code and as base32 text
   such as `JBSWY3DPEHPK3PXP`. The QR code is only an `otpauth://totp/Name?secret=…&issuer=…` link. Both sides now store the seed.
2. **Each code.** Both sides compute `counter = floor(unix_time / 30)`, then `HMAC-SHA1(seed, counter)` (RFC 6238, built on the
   counter-based HOTP of RFC 4226).
3. **Truncate.** The last nibble of the HMAC picks an offset; take 4 bytes from there, clear the top bit, and take the number
   modulo 10⁶. That is the six digits.
4. **Verify.** The site recomputes the code and compares. It usually also accepts the previous and next 30-second step, to
   tolerate clock drift (Strongbox's `kit/server/totp.js` accepts ±1).

Properties worth knowing:

- Nothing travels between phone and site after setup, so it works offline.
- A code is useless 30 seconds later. Good sites also refuse a code that was already used.
- **Whoever has the seed has every future code.** The seed is the real secret, not the digits.
- Only the clocks have to agree, which is why a badly wrong phone clock makes valid codes "wrong".

## Recovery codes

Sites give you about ten one-time backup codes at setup. They are plain random strings, stored hashed by the site, and they
exist for the day the phone is lost. Treat them like passwords. Strongbox's Websites type has a *Recovery codes* secret field.

## Security keys (FIDO2 / WebAuthn)

1. **Registration.** The key makes a key pair for that site. The site stores the public key.
2. **Login.** The site sends a random challenge. The key signs it with the private key (after a touch), and the signature
   covers the website's origin. The site checks the signature.
3. **Phishing resistance.** A fake site has a different origin, so the key refuses or the real site rejects the result. There
   is no code a user can be tricked into typing.
4. **Nothing to steal.** The private key never leaves the device, so there is nothing useful on the server side either.

## Where Strongbox uses it

**1. Signing in to Strongbox itself** (Security page → Two-factor codes). The kit makes a TOTP seed for the admin account and
shows the QR code. You confirm with one code, and from then on sign-in needs the password and a code. The server checks it with the
±1 step window. Turning it off asks for the password.

**2. Authenticator codes stored inside entries** (the *Authenticator seed* field, on entries and on each account). Strongbox acts
as the authenticator for that site. *Show code* asks the server to compute the six digits from the encrypted seed, with a 30-second
countdown. The seed is never sent to the browser, only the current code, and each use is logged.

> **Caveat.** If the password and the seed sit in the same vault, anyone who opens the vault gets both factors, so for that
> account you effectively have one factor, not two. That is still much better than a reused password, but for the accounts that
> matter most (email, Google, banking) keep the seed in a separate authenticator app or on a hardware key.

**3. Opening the vault** (passphrase + key file, or passphrase + hardware security key). This is the same "know + have" idea
applied to the vault's encryption key. It works differently from website 2FA: the key file's 32 random bytes, or a secret computed by
the security key, are mixed with the passphrase in the key derivation (scrypt → HKDF). Without the second factor the key cannot be
computed at all, so the vault is not merely checked, it cannot be decrypted. A stolen backup is useless without both.

**4. The security-key unlock in detail.** The browser uses the WebAuthn **PRF extension**: the key computes a 32-byte value from a
salt Strongbox gives it, and the value is the same every time. That value takes the place of a key file. The credential is tied to the
host name it was created on (`rpId`), which is why this mode always comes with a recovery key: opening Strongbox from another address
cannot use the key. At setup the secret is read twice and must match before it is used for anything. This path has not yet been tested
against a physical key.

## Practical advice

- Prefer a security key or an authenticator app over SMS.
- Keep the seed and the password on **different** devices for important accounts.
- Save recovery codes at setup, not afterwards.
- Keep a spare security key; never register just one.
