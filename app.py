import base64
from pathlib import Path

import streamlit as st

from crypto_algorithms import (
    diffie_hellman_exchange,
    ecc_diffie_hellman,
    generate_rsa_components,
    rsa_decrypt_numbers,
    rsa_encrypt_text,
    aes_encrypt_text,
    aes_decrypt_text,
)
from primality_tests import aks_test, fermat_test, miller_rabin_test, solovay_strassen_test


st.set_page_config(page_title="Cryptography Visualizer", page_icon="🔐", layout="wide")


def apply_custom_styles() -> None:
    bg_path = Path(__file__).parent / "assets" / "crypto_bg.svg"
    bg_data = ""
    if bg_path.exists():
        bg_data = base64.b64encode(bg_path.read_bytes()).decode("utf-8")

    background_layer = (
        f"url('data:image/svg+xml;base64,{bg_data}')"
        if bg_data
        else "radial-gradient(circle at 20% 15%, #0e7490 0%, rgba(14, 116, 144, 0) 45%), radial-gradient(circle at 85% 0%, #b45309 0%, rgba(180, 83, 9, 0) 40%), linear-gradient(135deg, #001a2d 0%, #0b3c5d 55%, #04263f 100%)"
    )

    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

        :root {{
            --text-main: #e6f1fb;
            --text-soft: #c7d8e8;
            --card-bg: rgba(3, 24, 40, 0.62);
            --card-border: rgba(159, 231, 216, 0.35);
        }}

        .stApp {{
            background-image:
                radial-gradient(circle at 15% 5%, rgba(16, 185, 129, 0.17), transparent 33%),
                radial-gradient(circle at 85% 8%, rgba(245, 158, 11, 0.20), transparent 32%),
                {background_layer};
            background-attachment: fixed;
            background-size: cover;
            color: var(--text-main);
            font-family: 'Space Grotesk', sans-serif;
        }}

        [data-testid="stHeader"] {{
            background: rgba(2, 18, 30, 0.55);
            border-bottom: 1px solid rgba(159, 231, 216, 0.22);
            backdrop-filter: blur(8px);
        }}

        [data-testid="stSidebar"] {{
            background: linear-gradient(180deg, rgba(1, 22, 35, 0.88), rgba(2, 44, 58, 0.76));
            border-right: 1px solid rgba(159, 231, 216, 0.25);
            backdrop-filter: blur(8px);
        }}

        [data-testid="stSidebar"] * {{
            color: var(--text-main) !important;
        }}

        h1, h2, h3 {{
            color: #fff7e9;
            letter-spacing: 0.2px;
            text-shadow: 0 8px 22px rgba(0, 0, 0, 0.35);
        }}

        .stMarkdown p, .stCaption {{
            color: var(--text-soft);
        }}

        .block-container {{
            animation: fade-slide 600ms ease-out both;
            padding-top: 1.6rem;
            padding-bottom: 2rem;
        }}

        @keyframes fade-slide {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        [data-testid="stTabs"] [role="tab"] {{
            border-radius: 10px;
            border: 1px solid rgba(159, 231, 216, 0.36);
            background: rgba(2, 26, 42, 0.5);
            color: var(--text-main);
        }}

        [data-testid="stTabs"] [aria-selected="true"] {{
            background: linear-gradient(95deg, rgba(14, 116, 144, 0.7), rgba(217, 119, 6, 0.6));
            color: #fff;
            border-color: rgba(245, 158, 11, 0.85);
        }}

        [data-testid="stTextInput"],
        [data-testid="stNumberInput"],
        [data-testid="stSelectbox"],
        [data-testid="stTextArea"],
        [data-testid="stMultiSelect"],
        [data-testid="stSlider"],
        [data-testid="stRadio"] {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            padding: 0.35rem 0.55rem;
            box-shadow: 0 10px 26px rgba(1, 8, 15, 0.35);
            backdrop-filter: blur(4px);
        }}

        [data-testid="stDataFrame"] {{
            border: 1px solid var(--card-border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 24px rgba(1, 8, 15, 0.34);
        }}

        code {{
            color: #ffdf9f;
            background: rgba(6, 37, 57, 0.74);
            border: 1px solid rgba(245, 158, 11, 0.26);
            border-radius: 6px;
            padding: 0.12rem 0.3rem;
            font-family: 'IBM Plex Mono', monospace;
        }}

        @media (max-width: 860px) {{
            .block-container {{
                padding-top: 1.1rem;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    st.markdown(
        """
        <div style="padding: 0.9rem 1.1rem; border-radius: 14px; border: 1px solid rgba(159,231,216,0.35); background: linear-gradient(100deg, rgba(7,46,68,0.72), rgba(125,77,18,0.55)); box-shadow: 0 14px 34px rgba(1,10,18,0.42); margin-bottom: 0.9rem;">
            <h1 style="margin: 0;">Cryptography and Primality Test Visualizer</h1>
            <p style="margin: 0.25rem 0 0; color: #d2e6f6;">Interactive demos for AES, RSA, Diffie-Hellman, ECC, and primality tests.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_aes() -> None:
    st.subheader("AES (Educational Demo)")
    st.caption("Uses AES-128 ECB for transparency of internals; this mode is not recommended for production.")

    plaintext = st.text_area("Plaintext", value="Hello cryptography")
    passphrase = st.text_input("Passphrase", value="demo-key")

    try:
        ciphertext_hex, enc_steps = aes_encrypt_text(plaintext, passphrase)
        st.text_input("Ciphertext (hex)", value=ciphertext_hex)
        st.write("Encryption steps")
        st.dataframe(enc_steps, width="stretch", hide_index=True)

        decrypted_text, dec_steps = aes_decrypt_text(ciphertext_hex, passphrase)
        st.text_input("Decrypted plaintext", value=decrypted_text)
        st.write("Decryption steps")
        st.dataframe(dec_steps, width="stretch", hide_index=True)
    except ValueError as exc:
        st.error(str(exc))


def render_rsa() -> None:
    st.subheader("RSA — Chiffrement Asymétrique")

    # ── Introduction ──────────────────────────────────────────────
    st.markdown(
        """
        **RSA** (Rivest–Shamir–Adleman, 1977) est un algorithme de chiffrement **asymétrique** :
        il utilise une paire de clés — une **clé publique** pour chiffrer et une **clé privée** pour déchiffrer.
        Sa sécurité repose sur la difficulté de **factoriser** un grand entier `n = p × q`.

        ---
        ### Étape 1 — Choisir deux nombres premiers distincts `p` et `q`
        Ces deux premiers sont **secrets**. Leur produit `n` forme le **module RSA** utilisé publiquement.
        > Si `p = q`, RSA est immédiatement cassable (il suffit de calculer √n).
        """
    )

    prime_options = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    col1, col2, col3 = st.columns(3)
    with col1:
        p = st.selectbox("Premier p", options=prime_options, index=0)
    with col2:
        q = st.selectbox("Premier q", options=prime_options, index=1)
    with col3:
        e = st.number_input("Exposant public e", min_value=3, value=5, step=2)

    if p == q:
        st.error("`p` et `q` doivent être différents — sinon RSA est trivial à casser.")
        return

    st.markdown(
        """
        ---
        ### Étape 2 — Calculer `n` et `φ(n)`
        - **`n = p × q`** : le module RSA, partagé publiquement.
        - **`φ(n) = (p−1)(q−1)`** : l'indicatrice d'Euler, gardée **secrète**.
          Elle représente le nombre d'entiers inférieurs à `n` qui sont premiers avec lui.
        """
    )

    message = st.text_input("Message à chiffrer", value="HELLO")

    try:
        values = generate_rsa_components(p, q, int(e))
    except ValueError as exc:
        st.error(str(exc))
        return

    st.info(
        f"`n = p × q = {p} × {q} = {values['n']}`  \n"
        f"`φ(n) = (p−1)(q−1) = {p-1} × {q-1} = {values['phi']}`"
    )

    st.markdown(
        f"""
        ---
        ### Étape 3 — Choisir l'exposant public `e`
        `e` doit vérifier **1 < e < φ(n)** et **pgcd(e, φ(n)) = 1** (e premier avec φ(n)).
        La clé publique est la paire **`(e={values['e']}, n={values['n']})`** — partageable avec tout le monde.

        ---
        ### Étape 4 — Calculer l'exposant privé `d`
        `d` est l'**inverse modulaire** de `e` modulo `φ(n)`, calculé via l'algorithme d'Euclide Étendu :
        > `e × d ≡ 1 (mod φ(n))`

        La clé privée est **`d = {values['d']}`** — à ne **jamais** divulguer.
        """
    )

    st.success(
        f"Clé publique  : `(e={values['e']}, n={values['n']})`  \n"
        f"Clé privée    : `d = {values['d']}`"
    )

    # ── Chiffrement ───────────────────────────────────────────────
    st.markdown(
        """
        ---
        ### Étape 5 — Chiffrement
        Chaque lettre du message est convertie en sa valeur ASCII, puis chiffrée :
        > `C = M^e mod n`

        Le résultat `C` est le **chiffré** — illisible sans la clé privée `d`.
        """
    )

    try:
        ciphertext, enc_steps = rsa_encrypt_text(message, values["n"], values["e"])
    except ValueError as exc:
        st.warning(str(exc))
        return

    st.text_input("Chiffré (entiers)", value=", ".join(str(x) for x in ciphertext))

    with st.expander("Voir les étapes de chiffrement lettre par lettre"):
        st.dataframe(enc_steps, use_container_width=True, hide_index=True)

    # ── Déchiffrement ─────────────────────────────────────────────
    st.markdown(
        """
        ---
        ### Étape 6 — Déchiffrement
        Le destinataire utilise sa clé privée `d` pour retrouver le message original :
        > `M = C^d mod n`

        Grâce à la propriété d'Euler : `(M^e)^d ≡ M (mod n)`.
        """
    )

    decrypted, dec_steps = rsa_decrypt_numbers(ciphertext, values["n"], values["d"])
    st.text_input("Message déchiffré", value=decrypted)

    with st.expander("Voir les étapes de déchiffrement"):
        st.dataframe(dec_steps, use_container_width=True, hide_index=True)

    # ── Note sécurité ─────────────────────────────────────────────
    st.markdown(
        """
        ---
        ### Note sur la sécurité
        Cette démo utilise de **petits nombres premiers** pour la lisibilité.
        En pratique, RSA sécurisé utilise des clés de **2048 à 4096 bits**
        (nombres de plusieurs centaines de chiffres) rendant la factorisation de `n` computationnellement infaisable.
        """
    )

def render_diffie_hellman() -> None:
    st.subheader("Diffie-Hellman Key Exchange")

    p = st.number_input("Prime modulus p", min_value=11, value=23, step=1)
    g = st.number_input("Generator g", min_value=2, value=5, step=1)
    private_a = st.number_input("Alice private key a", min_value=2, value=6, step=1)
    private_b = st.number_input("Bob private key b", min_value=2, value=15, step=1)

    try:
        values, steps = diffie_hellman_exchange(int(p), int(g), int(private_a), int(private_b))
    except ValueError as exc:
        st.error(str(exc))
        return

    st.write(f"`A = {values['public_a']}`")
    st.write(f"`B = {values['public_b']}`")
    st.success(f"Shared secret: `{values['shared_a']}`")

    st.dataframe(steps, width="stretch", hide_index=True)


def render_ecc() -> None:
    st.subheader("ECC Diffie-Hellman (secp256k1)")

    private_a = st.number_input("Alice private scalar", min_value=1, value=12345, step=1)
    private_b = st.number_input("Bob private scalar", min_value=1, value=67890, step=1)

    try:
        values, steps = ecc_diffie_hellman(int(private_a), int(private_b))
    except ValueError as exc:
        st.error(str(exc))
        return

    st.write(f"Curve: `{values['curve']}`")
    st.write(f"Alice public x: `{values['public_a_x']}`")
    st.write(f"Bob public x: `{values['public_b_x']}`")
    st.success(f"Shared x-coordinate: `{values['shared_x']}`")

    st.dataframe(steps, width="stretch", hide_index=True)



def render_algorithms() -> None:
    st.subheader("Cryptography Algorithms")
    aes_tab, rsa_tab, dh_tab, ecc_tab = st.tabs(["AES", "RSA", "Diffie-Hellman", "ECC"])

    with aes_tab:
        render_aes()
    with rsa_tab:
        render_rsa()
    with dh_tab:
        render_diffie_hellman()
    with ecc_tab:
        render_ecc()


def render_primality_tests() -> None:
    st.subheader("Primality Tests")
    st.caption("AKS is deterministic but computationally heavy; keep numbers moderate for quick interaction.")

    n = st.number_input("Number to test", min_value=2, value=101, step=1)
    rounds = st.slider("Random rounds", min_value=1, max_value=12, value=5)
    seed = st.number_input("Random seed", min_value=0, value=42, step=1)

    tests = st.multiselect(
        "Choose tests",
        ["Fermat", "Miller-Rabin", "AKS", "Solovay-Strassen"],
        default=["Fermat", "Miller-Rabin", "AKS", "Solovay-Strassen"],
    )

    if "Fermat" in tests:
        result, steps = fermat_test(int(n), rounds=rounds, seed=int(seed))
        st.markdown(f"**Fermat:** {'Probably prime' if result else 'Composite'}")
        st.dataframe(steps, width="stretch", hide_index=True)

    if "Miller-Rabin" in tests:
        result, steps = miller_rabin_test(int(n), rounds=rounds, seed=int(seed))
        st.markdown(f"**Miller-Rabin:** {'Probably prime' if result else 'Composite'}")
        st.dataframe(steps, width="stretch", hide_index=True)

    if "AKS" in tests:
        if int(n) > 350:
            st.info("AKS can be slow on larger numbers in this educational implementation.")
        result, steps = aks_test(int(n))
        st.markdown(f"**AKS:** {'Prime' if result else 'Composite'}")
        st.dataframe(steps, width="stretch", hide_index=True)

    if "Solovay-Strassen" in tests:
        result, steps = solovay_strassen_test(int(n), rounds=rounds, seed=int(seed))
        st.markdown(f"**Solovay-Strassen:** {'Probably prime' if result else 'Composite'}")
        st.dataframe(steps, width="stretch", hide_index=True)


def main() -> None:
    apply_custom_styles()
    render_header()

    page = st.sidebar.radio("Choose module", ["Algorithms", "Primality Tests"])

    if page == "Algorithms":
        render_algorithms()
    else:
        render_primality_tests()


if __name__ == "__main__":
    main()
