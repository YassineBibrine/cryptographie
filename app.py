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
            --accent-cyan: #67e8f9;
            --accent-gold: #fbbf24;
            --panel-bg: rgba(5, 30, 47, 0.72);
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

        /* Input fields */
        [data-testid="stTextInput"] input,
        [data-testid="stNumberInput"] input,
        [data-testid="stTextArea"] textarea,
        [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
        [data-testid="stMultiSelect"] div[data-baseweb="select"] > div {{
            background: linear-gradient(180deg, rgba(8, 43, 65, 0.85), rgba(4, 26, 40, 0.88));
            border: 1px solid rgba(103, 232, 249, 0.4) !important;
            border-radius: 10px !important;
            color: #eef8ff !important;
        }}

        [data-testid="stTextInput"] label,
        [data-testid="stNumberInput"] label,
        [data-testid="stTextArea"] label,
        [data-testid="stSelectbox"] label,
        [data-testid="stSlider"] label,
        [data-testid="stMultiSelect"] label {{
            font-weight: 600;
            color: #e9f5ff !important;
            letter-spacing: 0.2px;
        }}

        [data-testid="stTextInput"] input:focus,
        [data-testid="stNumberInput"] input:focus,
        [data-testid="stTextArea"] textarea:focus {{
            border-color: rgba(251, 191, 36, 0.85) !important;
            box-shadow: 0 0 0 1px rgba(251, 191, 36, 0.65), 0 0 0 4px rgba(251, 191, 36, 0.16);
        }}

        /* Dataframes and tables */
        [data-testid="stDataFrame"] {{
            border: 1px solid rgba(103, 232, 249, 0.38);
            border-radius: 14px;
            overflow: hidden;
            box-shadow: 0 12px 30px rgba(1, 8, 15, 0.4);
            background: linear-gradient(180deg, rgba(5, 34, 52, 0.85), rgba(4, 23, 36, 0.88));
        }}

        [data-testid="stDataFrame"] thead tr th {{
            background: linear-gradient(90deg, rgba(8, 71, 92, 0.95), rgba(13, 104, 111, 0.92));
            color: #f5fcff !important;
            border-bottom: 1px solid rgba(251, 191, 36, 0.5) !important;
            font-weight: 700 !important;
        }}

        [data-testid="stDataFrame"] tbody tr:nth-child(odd) td {{
            background: rgba(7, 38, 58, 0.62) !important;
        }}

        [data-testid="stDataFrame"] tbody tr:nth-child(even) td {{
            background: rgba(4, 28, 43, 0.6) !important;
        }}

        [data-testid="stDataFrame"] tbody tr:hover td {{
            background: rgba(18, 72, 94, 0.72) !important;
        }}

        .home-card {{
            background: linear-gradient(160deg, rgba(6, 40, 61, 0.78), rgba(8, 28, 44, 0.78));
            border: 1px solid rgba(103, 232, 249, 0.35);
            border-radius: 14px;
            padding: 0.95rem 1rem;
            box-shadow: 0 12px 28px rgba(1, 10, 18, 0.4);
            margin-bottom: 0.8rem;
        }}

        .home-card h3 {{
            margin: 0 0 0.35rem 0;
            color: #fff4dd;
        }}

        .home-card p {{
            margin: 0;
            color: #d6e9f7;
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


def render_home() -> None:
    st.subheader("Home")
    st.markdown(
        """
        This app is an educational cryptography lab.
        It helps you understand how core algorithms and primality tests work, then lets you run them with your own values.
        """
    )

    st.markdown(
        """
        <div class="home-card">
            <h3>What You Can Explore</h3>
            <p>AES, RSA, Diffie-Hellman, ECC Diffie-Hellman, and four primality tests (Fermat, Miller-Rabin, AKS, Solovay-Strassen).</p>
        </div>
        <div class="home-card">
            <h3>How Each Page Is Organized</h3>
            <p>Each algorithm/test page follows the same learning flow: logic overview, execution walkthrough, then an interactive test area.</p>
        </div>
        <div class="home-card">
            <h3>What To Do Next</h3>
            <p>Start in <code>Algorithms</code> for encryption/key-exchange demos, then move to <code>Primality Tests</code> to compare testing methods.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        st.info("Use small to medium numbers first to keep computations responsive.")
    with col2:
        st.success("Open any tab and inspect the execution trace after running a test.")


def render_aes() -> None:
    st.subheader("AES (Educational Demo)")
    st.caption("Uses AES-128 ECB for transparency of internals; this mode is not recommended for production.")

    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        AES is a symmetric block cipher: the same secret key encrypts and decrypts data.
        In this demo, we derive a 128-bit key from a passphrase, pad plaintext to 16-byte blocks,
        then encrypt with ECB mode so each internal step stays easy to inspect.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Convert plaintext to bytes.
        2. Derive a 128-bit key from the passphrase (SHA-256, first 16 bytes).
        3. Add PKCS7 padding to fit AES block size.
        4. Encrypt each block with AES-128 ECB.
        5. For decryption, reverse: decrypt blocks then remove padding.
        """
    )
    phase2_trace = st.container()

    st.markdown("### Test the Algorithm")

    plaintext = st.text_area("Plaintext", value="Hello cryptography")
    passphrase = st.text_input("Passphrase", value="demo-key")

    try:
        ciphertext_hex, enc_steps = aes_encrypt_text(plaintext, passphrase)
        st.text_input("Ciphertext (hex)", value=ciphertext_hex)

        decrypted_text, dec_steps = aes_decrypt_text(ciphertext_hex, passphrase)
        st.text_input("Decrypted plaintext", value=decrypted_text)

        with phase2_trace:
            st.write("Execution trace from your latest test")
            st.write("Encryption steps")
            st.dataframe(enc_steps, width="stretch", hide_index=True)
            st.write("Decryption steps")
            st.dataframe(dec_steps, width="stretch", hide_index=True)
    except ValueError as exc:
        st.error(str(exc))


def render_rsa() -> None:
    st.subheader("RSA — Chiffrement Asymétrique")

    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        RSA is an asymmetric algorithm: a public key encrypts and a private key decrypts.
        We build keys from two primes `p` and `q`, then compute:
        `n = p*q`, `phi = (p-1)*(q-1)`, and private exponent `d` such that `e*d = 1 mod phi`.
        Encryption uses `C = M^e mod n` and decryption uses `M = C^d mod n`.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Choose two distinct primes `p` and `q`.
        2. Compute `n = p*q` and `phi = (p-1)*(q-1)`.
        3. Choose public exponent `e` coprime with `phi`.
        4. Compute private exponent `d` as inverse of `e` modulo `phi`.
        5. Encrypt each character value with `c = m^e mod n`.
        6. Decrypt each encrypted value with `m = c^d mod n`.
        """
    )
    phase2_trace = st.container()

    st.markdown("### Test the Algorithm")

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

    st.success(
        f"Clé publique  : `(e={values['e']}, n={values['n']})`  \n"
        f"Clé privée    : `d = {values['d']}`"
    )

    try:
        ciphertext, enc_steps = rsa_encrypt_text(message, values["n"], values["e"])
    except ValueError as exc:
        st.warning(str(exc))
        return

    st.text_input("Chiffré (entiers)", value=", ".join(str(x) for x in ciphertext))

    decrypted, dec_steps = rsa_decrypt_numbers(ciphertext, values["n"], values["d"])
    st.text_input("Message déchiffré", value=decrypted)

    with phase2_trace:
        with st.expander("Execution trace - encryption"):
            st.dataframe(enc_steps, use_container_width=True, hide_index=True)
        with st.expander("Execution trace - decryption"):
            st.dataframe(dec_steps, use_container_width=True, hide_index=True)

def render_diffie_hellman() -> None:
    st.subheader("Diffie-Hellman Key Exchange")
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        Diffie-Hellman lets two parties derive a shared secret over a public channel.
        Alice and Bob publish only derived public values, while their private exponents stay hidden,
        and both sides compute the same secret thanks to modular exponentiation properties.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Publicly choose a prime modulus `p` and a generator `g`.
        2. Alice picks secret `a`, Bob picks secret `b`.
        3. Alice publishes `A = g^a mod p`, Bob publishes `B = g^b mod p`.
        4. Alice computes `s = B^a mod p`, Bob computes `s = A^b mod p`.
        5. Both results are equal and become the shared secret.
        """
    )
    phase2_trace = st.container()

    st.markdown("### Test the Algorithm")

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

    with phase2_trace:
        st.write("Execution trace from your latest test")
        st.dataframe(steps, width="stretch", hide_index=True)


def render_ecc() -> None:
    st.subheader("ECC Diffie-Hellman (secp256k1)")
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        ECC Diffie-Hellman is the elliptic-curve version of key exchange.
        Instead of modular integers, it uses point multiplication on secp256k1,
        giving strong security with shorter keys and the same shared-secret principle.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Both parties use the same curve parameters and base point `G`.
        2. Alice picks private scalar `a`, Bob picks private scalar `b`.
        3. Alice publishes `PA = a*G`, Bob publishes `PB = b*G`.
        4. Alice computes `S = a*PB`, Bob computes `S = b*PA`.
        5. Both obtain the same elliptic-curve shared point.
        """
    )
    phase2_trace = st.container()

    st.markdown("### Test the Algorithm")

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

    with phase2_trace:
        st.write("Execution trace from your latest test")
        st.dataframe(steps, width="stretch", hide_index=True)



def render_algorithms() -> None:
    st.subheader("Cryptography Algorithms")
    st.markdown(
        """
        This page summarizes four core cryptographic ideas: symmetric encryption (AES),
        asymmetric encryption (RSA), modular key exchange (Diffie-Hellman), and elliptic-curve key exchange (ECC).
        In each tab, read the explanation phase first, then run the execution phase.
        """
    )
    aes_tab, rsa_tab, dh_tab, ecc_tab = st.tabs(["AES", "RSA", "Diffie-Hellman", "ECC"])

    with aes_tab:
        render_aes()
    with rsa_tab:
        render_rsa()
    with dh_tab:
        render_diffie_hellman()
    with ecc_tab:
        render_ecc()


def render_fermat_test_page() -> None:
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        Fermat is a fast probabilistic primality test.
        For prime `n`, many bases `a` satisfy `a^(n-1) mod n = 1`.
        If one base violates this rule, `n` is definitely composite.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Choose random bases `a` between `2` and `n-2`.
        2. Compute `a^(n-1) mod n` for each round.
        3. If any result is not `1`, mark `n` as composite.
        4. If all rounds pass, return probably prime.
        """
    )
    trace_container = st.container()

    st.markdown("### Test the Algorithm")
    n = st.number_input("Number to test", min_value=2, value=101, step=1, key="fermat_n")
    rounds = st.slider("Random rounds", min_value=1, max_value=12, value=5, key="fermat_rounds")
    seed = st.number_input("Random seed", min_value=0, value=42, step=1, key="fermat_seed")

    result, steps = fermat_test(int(n), rounds=rounds, seed=int(seed))
    st.markdown(f"**Fermat:** {'Probably prime' if result else 'Composite'}")

    with trace_container:
        st.markdown("**Execution trace (latest test)**")
        st.dataframe(steps, width="stretch", hide_index=True)


def render_miller_rabin_test_page() -> None:
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        Miller-Rabin is a stronger probabilistic test than Fermat.
        It analyzes modular powers with repeated squaring to detect non-primes.
        A detected witness proves compositeness immediately.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Decompose `n-1 = 2^s * d` with odd `d`.
        2. Pick random base `a` and compute `x = a^d mod n`.
        3. If `x` is not `1` or `n-1`, repeatedly square `x`.
        4. If no valid `n-1` appears, `n` is composite.
        """
    )
    trace_container = st.container()

    st.markdown("### Test the Algorithm")
    n = st.number_input("Number to test", min_value=2, value=101, step=1, key="mr_n")
    rounds = st.slider("Random rounds", min_value=1, max_value=12, value=5, key="mr_rounds")
    seed = st.number_input("Random seed", min_value=0, value=42, step=1, key="mr_seed")

    result, steps = miller_rabin_test(int(n), rounds=rounds, seed=int(seed))
    st.markdown(f"**Miller-Rabin:** {'Probably prime' if result else 'Composite'}")

    with trace_container:
        st.markdown("**Execution trace (latest test)**")
        st.dataframe(steps, width="stretch", hide_index=True)


def render_aks_test_page() -> None:
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        AKS is a deterministic primality test.
        It uses number-theoretic and polynomial congruence checks, with no randomness.
        If all checks pass, primality is proven.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Reject `n` if it is a perfect power.
        2. Find a suitable `r` from multiplicative-order conditions.
        3. Check gcd conditions for small factors.
        4. Verify required polynomial congruences.
        """
    )
    trace_container = st.container()

    st.markdown("### Test the Algorithm")
    n = st.number_input("Number to test", min_value=2, value=101, step=1, key="aks_n")
    if int(n) > 350:
        st.info("AKS can be slow on larger numbers in this educational implementation.")

    result, steps = aks_test(int(n))
    st.markdown(f"**AKS:** {'Prime' if result else 'Composite'}")

    with trace_container:
        st.markdown("**Execution trace (latest test)**")
        st.dataframe(steps, width="stretch", hide_index=True)


def render_solovay_strassen_test_page() -> None:
    st.markdown("### Algorithm Logic")
    st.markdown(
        """
        Solovay-Strassen is a probabilistic test based on Euler criterion and Jacobi symbol.
        It compares two expressions that should match for primes.
        A mismatch gives a composite witness.
        """
    )

    st.markdown("### Step-by-Step Execution")
    st.markdown(
        """
        1. Pick a random base `a`.
        2. Compute `gcd(a, n)` and reject if it is non-trivial.
        3. Compute Euler value `a^((n-1)/2) mod n`.
        4. Compute Jacobi symbol `(a/n)` and compare.
        """
    )
    trace_container = st.container()

    st.markdown("### Test the Algorithm")
    n = st.number_input("Number to test", min_value=2, value=101, step=1, key="ss_n")
    rounds = st.slider("Random rounds", min_value=1, max_value=12, value=5, key="ss_rounds")
    seed = st.number_input("Random seed", min_value=0, value=42, step=1, key="ss_seed")

    result, steps = solovay_strassen_test(int(n), rounds=rounds, seed=int(seed))
    st.markdown(f"**Solovay-Strassen:** {'Probably prime' if result else 'Composite'}")

    with trace_container:
        st.markdown("**Execution trace (latest test)**")
        st.dataframe(steps, width="stretch", hide_index=True)


def render_primality_tests() -> None:
    st.subheader("Primality Tests")
    st.caption("AKS is deterministic but computationally heavy; keep numbers moderate for quick interaction.")
    st.markdown(
        """
        Each test now has its own tab, like the algorithm pages.
        Open one tab to study the method, review the execution logic, and run your own test.
        """
    )

    fermat_tab, mr_tab, aks_tab, ss_tab = st.tabs([
        "Fermat",
        "Miller-Rabin",
        "AKS",
        "Solovay-Strassen",
    ])

    with fermat_tab:
        render_fermat_test_page()
    with mr_tab:
        render_miller_rabin_test_page()
    with aks_tab:
        render_aks_test_page()
    with ss_tab:
        render_solovay_strassen_test_page()


def main() -> None:
    apply_custom_styles()
    render_header()

    page = st.sidebar.radio("Choose module", ["Home", "Algorithms", "Primality Tests"])

    if page == "Home":
        render_home()
    elif page == "Algorithms":
        render_algorithms()
    else:
        render_primality_tests()


if __name__ == "__main__":
    main()
