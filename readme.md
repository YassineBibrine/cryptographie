# Cryptography Visualizer (Streamlit)

An interactive Streamlit app to visualize:

- Classical ciphers (Caesar and Vigenere)
- RSA key generation, encryption, and decryption (educational scale)
- Primality tests (Trial Division, Fermat, Miller-Rabin)

## Features

- Step-by-step transformation tables for each algorithm
- Side-by-side RSA encryption/decryption traces
- Deterministic random seed for reproducible primality test rounds
- Simple UI with separate modules in the sidebar

## Project Structure

```text
.
|-- app.py
|-- crypto_algorithms.py
|-- primality_tests.py
|-- requirements.txt
|-- .gitignore
`-- readme.md
```

## Run Locally

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the app:

```bash
streamlit run app.py
```

4. Open the local URL shown in the terminal.

## Notes

- RSA values are intentionally small for clarity and learning.
- For real-world cryptography, use established libraries and secure key sizes.
