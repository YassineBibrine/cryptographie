from hashlib import sha256
from typing import Dict, List, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def is_coprime(a: int, b: int) -> bool:
    return gcd(a, b) == 1


def _mod_inverse(a: int, m: int) -> int:
    t, new_t = 0, 1
    r, new_r = m, a

    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r > 1:
        raise ValueError("a is not invertible modulo m")

    return t % m


def derive_aes_key(passphrase: str) -> bytes:
    return sha256(passphrase.encode("utf-8")).digest()[:16]


def aes_encrypt_text(plaintext: str, passphrase: str) -> Tuple[str, List[Dict[str, str]]]:
    key = derive_aes_key(passphrase)
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext_bytes = plaintext.encode("utf-8")
    padded = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded)

    steps = [
        {"step": "Key derivation", "value": f"SHA-256(passphrase)[:16] = {key.hex()}"},
        {"step": "Plaintext bytes", "value": plaintext_bytes.hex()},
        {"step": "PKCS7 padded", "value": padded.hex()},
        {"step": "AES-128 ECB ciphertext", "value": ciphertext.hex()},
    ]

    return ciphertext.hex(), steps


def aes_decrypt_text(ciphertext_hex: str, passphrase: str) -> Tuple[str, List[Dict[str, str]]]:
    key = derive_aes_key(passphrase)
    cipher = AES.new(key, AES.MODE_ECB)

    ciphertext = bytes.fromhex(ciphertext_hex.strip())
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)

    steps = [
        {"step": "Key derivation", "value": f"SHA-256(passphrase)[:16] = {key.hex()}"},
        {"step": "Ciphertext bytes", "value": ciphertext.hex()},
        {"step": "AES decrypt (padded)", "value": decrypted_padded.hex()},
        {"step": "PKCS7 unpadded", "value": decrypted.hex()},
    ]

    return decrypted.decode("utf-8", errors="replace"), steps


def generate_rsa_components(p: int, q: int, e: int) -> Dict[str, int]:
    if p == q:
        raise ValueError("p and q must be different primes")

    n = p * q
    phi = (p - 1) * (q - 1)
    if not is_coprime(e, phi):
        raise ValueError("e must be coprime with phi")

    d = _mod_inverse(e, phi)

    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def rsa_encrypt_text(text: str, n: int, e: int) -> Tuple[List[int], List[Dict[str, str]]]:
    ciphertext: List[int] = []
    steps: List[Dict[str, str]] = []

    for i, ch in enumerate(text):
        m = ord(ch)
        if m >= n:
            raise ValueError(f"Character '{ch}' has code {m} >= n={n}. Choose larger primes.")

        c = pow(m, e, n)
        ciphertext.append(c)
        steps.append(
            {
                "index": str(i),
                "char": ch,
                "m": str(m),
                "c = m^e mod n": str(c),
            }
        )

    return ciphertext, steps


def rsa_decrypt_numbers(ciphertext: List[int], n: int, d: int) -> Tuple[str, List[Dict[str, str]]]:
    chars: List[str] = []
    steps: List[Dict[str, str]] = []

    for i, c in enumerate(ciphertext):
        m = pow(c, d, n)
        ch = chr(m) if 0 <= m <= 0x10FFFF else "?"
        chars.append(ch)
        steps.append(
            {
                "index": str(i),
                "c": str(c),
                "m = c^d mod n": str(m),
                "char": ch,
            }
        )

    return "".join(chars), steps


def diffie_hellman_exchange(p: int, g: int, private_a: int, private_b: int) -> Tuple[Dict[str, int], List[Dict[str, str]]]:
    if not (2 <= private_a <= p - 2 and 2 <= private_b <= p - 2):
        raise ValueError("Private keys must be in [2, p-2].")
    if not (2 <= g <= p - 2):
        raise ValueError("Generator g must be in [2, p-2].")

    public_a = pow(g, private_a, p)
    public_b = pow(g, private_b, p)
    shared_a = pow(public_b, private_a, p)
    shared_b = pow(public_a, private_b, p)

    values = {
        "p": p,
        "g": g,
        "private_a": private_a,
        "private_b": private_b,
        "public_a": public_a,
        "public_b": public_b,
        "shared_a": shared_a,
        "shared_b": shared_b,
    }

    steps = [
        {"step": "Alice public key", "value": f"A = g^a mod p = {public_a}"},
        {"step": "Bob public key", "value": f"B = g^b mod p = {public_b}"},
        {"step": "Alice shared", "value": f"s = B^a mod p = {shared_a}"},
        {"step": "Bob shared", "value": f"s = A^b mod p = {shared_b}"},
    ]

    return values, steps


ECPoint = Optional[Tuple[int, int]]

# secp256k1 parameters
ECC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ECC_A = 0
ECC_B = 7
ECC_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
ECC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _short_hex(num: int) -> str:
    h = format(num, "x")
    if len(h) <= 16:
        return h
    return f"{h[:10]}...{h[-6:]}"


def _ecc_is_on_curve(point: ECPoint) -> bool:
    if point is None:
        return True

    x, y = point
    return (y * y - (x * x * x + ECC_A * x + ECC_B)) % ECC_P == 0


def _ecc_point_add(p1: ECPoint, p2: ECPoint) -> ECPoint:
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % ECC_P == 0:
        return None

    if p1 == p2:
        lam = (3 * x1 * x1 + ECC_A) * pow(2 * y1, -1, ECC_P)
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, ECC_P)

    lam %= ECC_P
    x3 = (lam * lam - x1 - x2) % ECC_P
    y3 = (lam * (x1 - x3) - y1) % ECC_P

    return x3, y3


def _ecc_scalar_mul(k: int, point: ECPoint) -> ECPoint:
    if point is None or k % ECC_N == 0:
        return None

    result: ECPoint = None
    addend = point

    while k > 0:
        if k & 1:
            result = _ecc_point_add(result, addend)
        addend = _ecc_point_add(addend, addend)
        k >>= 1

    return result


def ecc_diffie_hellman(private_a: int, private_b: int) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    if not (1 <= private_a < ECC_N and 1 <= private_b < ECC_N):
        raise ValueError("Private keys must be in [1, n-1].")

    public_a = _ecc_scalar_mul(private_a, ECC_G)
    public_b = _ecc_scalar_mul(private_b, ECC_G)
    if public_a is None or public_b is None:
        raise ValueError("Public key generation failed.")

    shared_a = _ecc_scalar_mul(private_a, public_b)
    shared_b = _ecc_scalar_mul(private_b, public_a)

    if shared_a is None or shared_b is None:
        raise ValueError("Shared secret generation failed.")

    if shared_a != shared_b:
        raise ValueError("ECC shared secrets do not match.")

    if not (_ecc_is_on_curve(public_a) and _ecc_is_on_curve(public_b) and _ecc_is_on_curve(shared_a)):
        raise ValueError("Generated point is not on curve.")

    values = {
        "curve": "secp256k1",
        "public_a_x": _short_hex(public_a[0]),
        "public_a_y": _short_hex(public_a[1]),
        "public_b_x": _short_hex(public_b[0]),
        "public_b_y": _short_hex(public_b[1]),
        "shared_x": _short_hex(shared_a[0]),
        "shared_y": _short_hex(shared_a[1]),
    }

    steps = [
        {"step": "Alice public point", "value": "PA = a * G"},
        {"step": "Bob public point", "value": "PB = b * G"},
        {"step": "Alice shared", "value": "S = a * PB"},
        {"step": "Bob shared", "value": "S = b * PA"},
        {"step": "Result", "value": "Both sides obtain the same elliptic-curve point."},
    ]

    return values, steps
