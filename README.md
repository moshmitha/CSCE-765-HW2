# CSCE 465/765 Homework 2 — Protect Agent Messages with Classic Cryptography

## Overview

This homework implements a cryptographic protocol for protecting messages exchanged between a local gateway and node.

The implementation contains:

- An AES-CTR baseline demonstrating why encryption without authentication is unsafe.
- An authenticated Diffie-Hellman/RSA handshake.
- A secure record layer using AES-256-CTR with HMAC-SHA-256.
- Automated security tests for handshake and record-layer attacks.

All cryptographic operations use the Python `cryptography` library rather than custom implementations of RSA, Diffie-Hellman, AES, SHA-256, or HMAC.

## Files

- `baseline_ctr.py` — AES-CTR-only baseline and tampering/replay demonstration.
- `handshake.py` — authenticated gateway/node handshake using RSA-PSS, ffdhe3072, nonces, transcript hashing, and key derivation.
- `secure_record.py` — AES-256-CTR + HMAC-SHA-256 protected record implementation.
- `ffdhe3072.pem` — standardized 3072-bit Diffie-Hellman parameter file.
- `tests/test_handshake.py` — automated handshake security tests.
- `tests/test_secure_record.py` — automated secure-record tests.

## Environment Setup

The homework was completed in the course VM.

From the project directory:

```bash
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
