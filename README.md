# AES Vault

Lock a message with a password, then watch AES scramble it: every substitution, shift, mix and key addition, one frame at a time. Everything runs in your browser; nothing is uploaded.

self-test running…

## Encrypt and decrypt

Output is Base64 text in the same format as the Python tool (salt, IV, AES-CBC with a 128, 192 or 256-bit key, HMAC), so the two are compatible.

Message to encrypt

Or load a file

Secret key (password). Decryption needs the exact same key.

Key size (decryption detects it automatically)

**Plaintext (first 24 bytes)**–

**Ciphertext (first 24 bytes)**–

## Watch AES work

One 16-byte block becomes a 4×4 grid of bytes. AES repeats four steps for 10, 12 or 14 rounds, depending on whether the key has 128, 192 or 256 bits. Press play, or drag the slider to scrub.

Block to encrypt (16 characters) AES version

Key (up to 32 characters, padded with zeros)

### State: the data

### Round key

Speed

SubBytesShiftRowsMixColumnsAddRoundKey

Educational implementation. For real data, use a vetted library.