"""
Simple File Encryption and Decryption using AES (implemented from scratch)
---------------------------------------------------------------------------
AES (128, 192 or 256-bit key) written by hand using the four round transformations:
    1. SubBytes      - byte substitution using the S-box
    2. ShiftRows     - cyclic left shift of each row of the state
    3. MixColumns    - matrix multiplication in GF(2^8) on each column
    4. AddRoundKey   - XOR of the state with the round key
plus Key Expansion. 10 / 12 / 14 rounds for 128 / 192 / 256-bit keys.

Mode of operation : CBC (random IV) with PKCS#7 padding
Key from password : PBKDF2-HMAC-SHA256 (Python standard library)
Wrong-key check   : HMAC-SHA256 over the encrypted file (encrypt-then-MAC)

No third-party libraries needed - only Python 3.8+.

GUI mode:  python aes_file_crypto.py
CLI mode:  python aes_file_crypto.py encrypt  report.pdf --bits 128   (128, 192 or 256)
           python aes_file_crypto.py decrypt  report.pdf.enc
           python aes_file_crypto.py preview  report.pdf.enc
           python aes_file_crypto.py demo --bits 192   (shows every step of one AES block)

Encrypted file layout:
    MAGIC (5) | KEY LENGTH (1) | SALT (16) | IV (16) | CIPHERTEXT | HMAC (32)

NOTE: This is an educational implementation (pure Python, not constant-time).
For real-world security use a vetted library such as `cryptography`.
"""

import argparse
import getpass
import hashlib
import hmac
import os
import sys

# ====================================================================
#  Part 1 : AES building blocks
# ====================================================================
NB = 4          # columns in the state (always 4 for AES)
# key size in bits -> (Nk = 32-bit words in the key, Nr = number of rounds)
KEY_SIZES = {128: (4, 10), 192: (6, 12), 256: (8, 14)}


def _build_sbox():
    """Generate the AES S-box (multiplicative inverse in GF(2^8) + affine map)."""
    sbox = [0] * 256
    p = q = 1
    while True:
        # p = p * 3
        p = (p ^ (p << 1) ^ (0x11B if p & 0x80 else 0)) & 0xFF
        # q = q / 3
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        rot = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def _gmul(a, b):
    """Multiply two bytes in GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else a << 1
        b >>= 1
    return r


# Pre-computed multiplication tables (speed-up for MixColumns)
MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


# ---------- the four transformations (state = 16 bytes, column-major) ----------
def sub_bytes(s):
    """Step 1: replace every byte using the S-box."""
    return [SBOX[b] for b in s]


def shift_rows(s):
    """Step 2: row r is rotated left by r positions."""
    return [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]


def mix_columns(s):
    """Step 3: multiply each column by the fixed MDS matrix in GF(2^8)."""
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
        out += [
            MUL[2][a0] ^ MUL[3][a1] ^ a2 ^ a3,
            a0 ^ MUL[2][a1] ^ MUL[3][a2] ^ a3,
            a0 ^ a1 ^ MUL[2][a2] ^ MUL[3][a3],
            MUL[3][a0] ^ a1 ^ a2 ^ MUL[2][a3],
        ]
    return out


def add_round_key(s, rk):
    """Step 4: XOR the state with the round key."""
    return [a ^ b for a, b in zip(s, rk)]


# ---------- inverse transformations (used for decryption) ----------
def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def inv_shift_rows(s):
    return [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]


def inv_mix_columns(s):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
        out += [
            MUL[14][a0] ^ MUL[11][a1] ^ MUL[13][a2] ^ MUL[9][a3],
            MUL[9][a0] ^ MUL[14][a1] ^ MUL[11][a2] ^ MUL[13][a3],
            MUL[13][a0] ^ MUL[9][a1] ^ MUL[14][a2] ^ MUL[11][a3],
            MUL[11][a0] ^ MUL[13][a1] ^ MUL[9][a2] ^ MUL[14][a3],
        ]
    return out


# ---------- key expansion ----------
def expand_key(key: bytes):
    """Expand a 16/24/32-byte key into Nr+1 round keys (each 16 bytes)."""
    assert len(key) in (16, 24, 32)
    nk = len(key) // 4              # 4, 6 or 8 words
    nr = nk + 6                     # 10, 12 or 14 rounds
    w = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, NB * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [SBOX[b] for b in t]                # SubWord
            t[0] ^= rcon
            rcon = ((rcon << 1) ^ 0x11B) & 0xFF if rcon & 0x80 else rcon << 1
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]                # extra SubWord, AES-256 only
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r: 4 * r + 4], []) for r in range(nr + 1)]


# ---------- block encryption / decryption ----------
def _hx(s):
    return bytes(s).hex(" ")


def encrypt_block(block: bytes, rks, trace=None):
    """Encrypt one 16-byte block. If `trace` is a list, each step is logged."""
    log = trace.append if trace is not None else (lambda _x: None)
    nr = len(rks) - 1               # 10, 12 or 14 rounds
    s = list(block)
    log(f"Input state           : {_hx(s)}")
    s = add_round_key(s, rks[0])
    log(f"Round  0 AddRoundKey  : {_hx(s)}")
    for rnd in range(1, nr):
        s = sub_bytes(s);       log(f"Round {rnd:2d} SubBytes    : {_hx(s)}")
        s = shift_rows(s);      log(f"Round {rnd:2d} ShiftRows   : {_hx(s)}")
        s = mix_columns(s);     log(f"Round {rnd:2d} MixColumns  : {_hx(s)}")
        s = add_round_key(s, rks[rnd]); log(f"Round {rnd:2d} AddRoundKey : {_hx(s)}")
    s = sub_bytes(s);           log(f"Round {nr:2d} SubBytes    : {_hx(s)}")
    s = shift_rows(s);          log(f"Round {nr:2d} ShiftRows   : {_hx(s)}")
    s = add_round_key(s, rks[nr]); log(f"Round {nr:2d} AddRoundKey : {_hx(s)}  (no MixColumns in last round)")
    return bytes(s)


def decrypt_block(block: bytes, rks):
    nr = len(rks) - 1
    s = add_round_key(list(block), rks[nr])
    for rnd in range(nr - 1, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, rks[rnd])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, rks[0])
    return bytes(s)


# ====================================================================
#  Part 2 : CBC mode, padding, password -> key
# ====================================================================
def pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Bad padding.")
    return data[:-n]


def cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    rks = expand_key(key)
    data, prev, out = pad(data), iv, bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(block, rks)
        out += prev
    return bytes(out)


def cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    rks = expand_key(key)
    prev, out = iv, bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(block, rks), prev))
        prev = block
    return unpad(bytes(out))


def derive_keys(password: str, salt: bytes, key_len: int = 32):
    """Password -> AES key (16/24/32 bytes) + 32-byte HMAC key."""
    material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, key_len + 32)
    return material[:key_len], material[key_len:]


# ====================================================================
#  Part 3 : file encryption / decryption
# ====================================================================
MAGIC = b"AESF3"    # AESF3 | key length (1 byte) | salt | iv | ciphertext | hmac
LEGACY = b"AESF2"   # older files: always AES-256, no key-length byte


def describe(bits: int) -> str:
    return f"AES-{bits} ({KEY_SIZES[bits][1]} rounds)"


def encrypt_file(in_path, password, out_path=None, bits=256):
    if bits not in KEY_SIZES:
        raise ValueError("Key size must be 128, 192 or 256.")
    with open(in_path, "rb") as f:
        plaintext = f.read()
    key_len = bits // 8
    salt, iv = os.urandom(16), os.urandom(16)
    aes_key, mac_key = derive_keys(password, salt, key_len)
    body = MAGIC + bytes([key_len]) + salt + iv + cbc_encrypt(plaintext, aes_key, iv)
    tag = hmac.new(mac_key, body, hashlib.sha256).digest()
    out_path = out_path or in_path + ".enc"
    with open(out_path, "wb") as f:
        f.write(body + tag)
    return out_path


def decrypt_file(in_path, password, out_path=None):
    """The key size is read from the file. Raises ValueError for a wrong key or a modified file."""
    with open(in_path, "rb") as f:
        data = f.read()
    if data.startswith(MAGIC):
        off, key_len = 6, data[5]
    elif data.startswith(LEGACY):
        off, key_len = 5, 32
    else:
        raise ValueError("This is not a file encrypted by this tool.")
    if key_len not in (16, 24, 32) or len(data) < off + 16 + 16 + 16 + 32:
        raise ValueError("This is not a file encrypted by this tool.")
    body, tag = data[:-32], data[-32:]
    salt, iv, ct = body[off:off + 16], body[off + 16:off + 32], body[off + 32:]
    aes_key, mac_key = derive_keys(password, salt, key_len)
    if not hmac.compare_digest(tag, hmac.new(mac_key, body, hashlib.sha256).digest()):
        raise ValueError("Decryption failed: wrong key or the file was modified.")
    if len(ct) % 16:
        raise ValueError("Corrupted file.")
    plaintext = cbc_decrypt(ct, aes_key, iv)
    if out_path is None:
        base = in_path[:-4] if in_path.endswith(".enc") else in_path
        root, ext = os.path.splitext(base)
        out_path = f"{root}_decrypted{ext}"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path


def preview(path, n=64):
    """First bytes of a file as text and hex (plaintext vs ciphertext)."""
    with open(path, "rb") as f:
        chunk = f.read(n)
    txt = "".join(c if c.isprintable() else "." for c in chunk.decode("utf-8", "replace"))
    return f"Text view : {txt}\nHex view  : {chunk.hex(' ')}"


VECTORS = {128: "69c4e0d86a7b0430d8cdb78070b4c55a",
           192: "dda97ca4864cdfe06eaf70a0ec0d7191",
           256: "8ea2b7ca516745bfeafc49904b496089"}


def demo(bits=256):
    """Show every transformation for one block (FIPS-197 Appendix C example)."""
    key = bytes(range(bits // 8))
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    steps = []
    ct = encrypt_block(block, expand_key(key), steps)
    print(f"{describe(bits)}: {bits // 8}-byte key\n")
    print("\n".join(steps))
    print("\nCiphertext :", ct.hex())
    print("Expected   :", VECTORS[bits], "(FIPS-197 Appendix C)")


# ====================================================================
#  Part 4 : command line + GUI
# ====================================================================
def run_cli(argv):
    p = argparse.ArgumentParser(description="AES file encryption tool (128/192/256-bit keys, from scratch)")
    p.add_argument("action", choices=["encrypt", "decrypt", "preview", "demo"])
    p.add_argument("file", nargs="?")
    p.add_argument("-o", "--output")
    p.add_argument("--bits", type=int, choices=[128, 192, 256], default=256,
                   help="AES key size for encrypt and demo (decrypt detects it)")
    a = p.parse_args(argv)

    if a.action == "demo":
        return demo(a.bits)
    if not a.file or not os.path.isfile(a.file):
        sys.exit("Please give an existing file.")
    if a.action == "preview":
        return print(preview(a.file))

    pw = getpass.getpass("Password: ")
    if a.action == "encrypt":
        if pw != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
        print("Encrypted ->", encrypt_file(a.file, pw, a.output, a.bits), "using", describe(a.bits))
    else:
        try:
            print("Decrypted ->", decrypt_file(a.file, pw, a.output))
        except ValueError as e:
            sys.exit(str(e))


def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("AES File Encryptor")
    path_var, pw_var = tk.StringVar(), tk.StringVar()
    bits_var = tk.IntVar(value=256)

    def log(msg):
        out.config(state="normal")
        out.insert("end", msg + "\n\n")
        out.see("end")
        out.config(state="disabled")

    def choose():
        p = filedialog.askopenfilename(
            filetypes=[("Text / PDF / Encrypted", "*.txt *.pdf *.enc"), ("All files", "*.*")])
        if p:
            path_var.set(p)
            log("Selected: " + p + "\n" + preview(p))

    def inputs():
        if not os.path.isfile(path_var.get()):
            messagebox.showerror("Error", "Please select a file first.")
        elif not pw_var.get():
            messagebox.showerror("Error", "Please enter a password (key).")
        else:
            return path_var.get(), pw_var.get()

    def work(fn, label):
        args = inputs()
        if not args:
            return
        root.config(cursor="watch"); root.update()
        try:
            res = fn(*args)
            log(f"{label} -> {res}\n" + preview(res))
            if label == "Encrypted":
                path_var.set(res)
        except ValueError as e:
            messagebox.showerror("Failed", str(e)); log("ERROR: " + str(e))
        finally:
            root.config(cursor="")

    tk.Label(root, text="File:").grid(row=0, column=0, padx=8, pady=8, sticky="e")
    tk.Entry(root, textvariable=path_var, width=55).grid(row=0, column=1)
    tk.Button(root, text="Browse...", command=choose).grid(row=0, column=2, padx=8)
    tk.Label(root, text="Password:").grid(row=1, column=0, padx=8, pady=8, sticky="e")
    tk.Entry(root, textvariable=pw_var, show="*", width=55).grid(row=1, column=1)
    fr = tk.Frame(root); fr.grid(row=2, column=0, columnspan=3, pady=10)
    tk.Label(fr, text="Key size:").pack(side="left")
    tk.OptionMenu(fr, bits_var, 128, 192, 256).pack(side="left", padx=(4, 14))
    tk.Button(fr, text="Encrypt", width=15,
              command=lambda: work(lambda f, pw: encrypt_file(f, pw, bits=bits_var.get()), "Encrypted")).pack(side="left", padx=10)
    tk.Button(fr, text="Decrypt", width=15,
              command=lambda: work(decrypt_file, "Decrypted")).pack(side="left", padx=10)
    out = tk.Text(root, height=15, width=75, state="disabled", wrap="word")
    out.grid(row=3, column=0, columnspan=3, padx=8, pady=4)
    root.mainloop()


if __name__ == "__main__":
    run_cli(sys.argv[1:]) if len(sys.argv) > 1 else run_gui()
