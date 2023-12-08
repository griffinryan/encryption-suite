# Cryptography CLI Suite in Java

### Overview

- Hashing library that implements SHA256, CSHAKE256, and KMACXOF256 algorithms.

- Able to hash a given file or user text input.

- Able to encrypt/decrypt a given file or text input using DHIES encryption and Schnorr signatures with elliptic curves.

_TODO: implement a file signing/verification feature_

---

All cryptographic algorthimic implementations are based of the National Institute of Standards and Technology's (NIST) specifications of the underlying Keccak algorithm and hashing algorithms based off of it.

You can read about SHA-3 Derived functions like cSHAKE and KMAC [here](https://dx.doi.org/10.6028/NIST.SP.800-185).
