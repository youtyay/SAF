<p align="left"><a href="#"><img src="https://img.shields.io/badge/project_quality-shitty_educational_demo-blue?style=plastic" alt="Project Quality Badge"></a></p>

<b>SAF(e) <i>(Simple As Fuck Encryption)</i></b> - A simplified (and unsafe) version of RSA for educational purposes and cryptographic fun.

---

# What Can it Do? 📃

* **Key Generation:** Generate RSA-like public and private key pairs of specified bit lengths.
* **Encryption:** Encrypt messages using a recipient's public key. It also supports optional digital signing of the message during encryption using the sender's private key.
* **Decryption:** Decrypt messages using a recipient's private key. It can also verify the sender's signature if the message was signed during encryption.
* **Digital Signature:** Sign a message using a private key to ensure its authenticity and integrity without encryption.
* **Signature Verification:** Verify a digital signature using the sender's public key to confirm the message's origin and that it hasn't been tampered with.

This project is analogous to a "Bubble Sort Algorithm" but in cryptography: it's inefficient and not suitable for production, but excellent for learning and understanding the basic mechanics.

---

# How it Works Under the Hood ℹ️

SAF implements a basic RSA-like algorithm in Python and JavaScript

### Core RSA Principles 🔐

RSA relies on the difficulty of factoring large composite numbers. Here's a simplified breakdown:

1.  **Key Generation:**
    * Two large **prime numbers**, `p` and `q`, are randomly generated.
    * The **modulus `n`** is calculated as `n = p * q`.
    * **Euler's totient function `phi(n)`** is calculated as `phi(n) = (p - 1) * (q - 1)`.
    * A **public exponent `e`** is chosen (commonly 65537), such that `1 < e < phi(n)` and `e` is coprime to `phi(n)`.
    * A **private exponent `d`** is calculated as the modular multiplicative inverse of `e` modulo `phi(n)`, i.e., `d * e ≡ 1 (mod phi(n))`.
    * The **Public Key** is `(e, n)`.
    * The **Private Key** is `(d, n)`.

2.  **Encryption:**
    * To encrypt a message `M` (converted to a number), the sender uses the recipient's **Public Key (e, n)**.
    * The ciphertext `C` is calculated as `C = M^e mod n`.
    * Messages are padded (PKCS#7-like padding) and broken into blocks if they exceed the key's block size, and each block is encrypted individually.
    * The encrypted message includes a header containing the original message length, padding length, and a flag indicating if the message was signed. It also includes an integrity check (either a signed hash or an encrypted hash).

3.  **Decryption:**
    * To decrypt a ciphertext `C`, the recipient uses their **Private Key (d, n)**.
    * The original message `M` is recovered by calculating `M = C^d mod n`.
    * The header is parsed to reconstruct the original message and verify integrity.

4.  **Digital Signature (Signing):**
    * The sender computes a **hash** of the message `M` (e.g., using SHA-256).
    * The hash `H` is then "encrypted" using the sender's **Private Key (d, n)**: `S = H^d mod n`. This `S` is the digital signature.
    * The signed message format includes the original message, the hash algorithm and value, and the Base64 encoded signature.

5.  **Signature Verification:**
    * The receiver computes their own hash `H'` of the received message.
    * They "decrypt" the received signature `S` using the **sender's Public Key (e, n)**: `H_retrieved = S^e mod n`.
    * If `H_retrieved` equals `H'`, the signature is valid, confirming the message's integrity and authenticity (i.e., it came from the owner of the private key corresponding to the public key used).

---

# Python Version Instructions 🐍

SAF also has the Python implementation and Nuitka-compiled version of it. In order to use it you should place script/executable into separate directory along with files you're planning to work with and run it.

---

# Contribute! 😸

I wouldn't call myself a professional developer, this is more a hobby project. Therefore, the code and implementation are fairly basic. Nevertheless, this project is open for your commits and suggestions. Whether you want to refine the existing code, suggest new features, or something else — everything's gonna make this project better :)
