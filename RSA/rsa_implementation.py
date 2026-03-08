# ─── rsa_implementation.py ──────────────────────────────────────
import math, unittest
from sympy import isprime, randprime


# ── Algorithme d'Euclide Étendu ─────────────────────────────────
def egcd(a, b):
    """Retourne (g, u, v) tels que a*u + b*v = g = pgcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, u, v = egcd(b % a, a)
    return g, v - (b // a) * u, u


def mod_inverse(e, phi):
    """Inverse modulaire de e modulo phi via Euclide Étendu."""
    g, u, _ = egcd(e % phi, phi)
    if g != 1:
        raise ValueError(f'pgcd({e}, {phi}) = {g} ≠ 1 — inverse inexistant')
    return u % phi


# ── Génération des clés RSA ──────────────────────────────────────
def generate_rsa_keys(bits=512):
    """Génère (pub_key, priv_key) = ((e,n), (d,n,p,q)) RSA."""
    p = randprime(2**(bits-1), 2**bits)
    q = randprime(2**(bits-1), 2**bits)
    while q == p or abs(p - q) < 2**(bits//2):  # Contre attaque Fermat
        q = randprime(2**(bits-1), 2**bits)
    n     = p * q
    phi_n = (p - 1) * (q - 1)
    e     = 65537                          # Exposant public standard
    assert math.gcd(e, phi_n) == 1, 'e doit être premier avec phi(n)'
    d = mod_inverse(e, phi_n)              # Exposant privé
    return (e, n), (d, n, p, q)


# ── Chiffrement / Déchiffrement standard ────────────────────────
def rsa_encrypt(M, pub_key):
    e, n = pub_key
    assert 0 < M < n, f'Message {M} doit être dans ]0, n['
    return pow(M, e, n)         # Exponentiation rapide O(log e · log²n)


def rsa_decrypt(C, priv_key):
    d, n, *_ = priv_key
    return pow(C, d, n)


# ── Déchiffrement optimisé CRT (Garner) — 4× plus rapide ────────
def rsa_decrypt_crt(C, priv_key):
    d, n, p, q = priv_key
    dp    = d % (p - 1)                    # d mod (p-1)
    dq    = d % (q - 1)                    # d mod (q-1)
    qInv  = mod_inverse(q, p)              # q^{-1} mod p
    Mp    = pow(C, dp, p)                  # M mod p
    Mq    = pow(C, dq, q)                  # M mod q
    h     = (qInv * (Mp - Mq)) % p         # Formule de Garner
    return Mq + q * h                      # Reconstruction CRT


# ════════════════════════════════════════════════════════════════
# TESTS UNITAIRES COMPLETS
# ════════════════════════════════════════════════════════════════
class TestRSA(unittest.TestCase):


    def setUp(self):
        """Génération des clés partagée par tous les tests."""
        self.pub, self.priv = generate_rsa_keys(bits=512)
        self.e, self.n      = self.pub
        self.d, self.n2, self.p, self.q = self.priv


    # ── Test 1 : Correction de base ──────────────────────────────
    def test_encrypt_decrypt_basic(self):
        for M in [1, 2, 42, 1000, 999999]:
            C  = rsa_encrypt(M, self.pub)
            M2 = rsa_decrypt(C, self.priv)
            self.assertEqual(M, M2, f'Échec pour M={M}')


    # ── Test 2 : Optimisation CRT donne même résultat ────────────
    def test_crt_vs_standard(self):
        for M in [7, 123, 4567]:
            C  = rsa_encrypt(M, self.pub)
            M1 = rsa_decrypt(C, self.priv)
            M2 = rsa_decrypt_crt(C, self.priv)
            self.assertEqual(M1, M2, 'CRT diverge de la méthode standard')


    # ── Test 3 : Propriété d'Euler — vérification directe ────────
    def test_euler_theorem(self):
        """Vérifie a^φ(n) ≡ 1 (mod n) pour a aléatoire."""
        phi_n = (self.p - 1) * (self.q - 1)
        for a in [3, 17, 257]:
            self.assertEqual(pow(a, phi_n, self.n), 1)


    # ── Test 4 : Relation e·d ≡ 1 (mod φ(n)) ────────────────────
    def test_key_pair_relation(self):
        phi_n = (self.p - 1) * (self.q - 1)
        self.assertEqual((self.e * self.d) % phi_n, 1,
                         'Relation e·d ≡ 1 (mod φ(n)) violée')


    # ── Test 5 : Cas limite — M = 1 et M = n-1 ───────────────────
    def test_boundary_messages(self):
        for M in [1, self.n - 1]:
            C  = rsa_encrypt(M, self.pub)
            M2 = rsa_decrypt(C, self.priv)
            self.assertEqual(M, M2, f'Cas limite M={M} échoue')


    # ── Test 6 : Message invalide — M ≥ n ────────────────────────
    def test_invalid_message_raises(self):
        with self.assertRaises(AssertionError):
            rsa_encrypt(self.n, self.pub)  # M = n interdit
        with self.assertRaises(AssertionError):
            rsa_encrypt(0, self.pub)       # M = 0 interdit


    # ── Test 7 : Inverse modulaire inexistant ────────────────────
    def test_no_inverse_raises(self):
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)  # pgcd(6,9) = 3 ≠ 1


if __name__ == '__main__':
    unittest.main(verbosity=2)
