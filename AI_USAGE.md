# AI Usage — CSCE 465/765 Homework 2

## AI Tool Information

- Tool: ChatGPT
- Model: GPT-5.6
- Date(s) used: October 3, 2026
- Purpose: Learning, implementation assistance, debugging, test design, and verification of the cryptographic homework implementation.

## AI Conversation Log

The relevant ChatGPT conversation was used during the development of this homework. The conversation includes assistance with:

- Understanding the assignment requirements and rubric.
- making the check list of the each task for submission
- Setting up the Python virtual environment and required packages.
- Understanding the AES-CTR baseline and its tampering/replay behavior.
- Implementing the authenticated Diffie-Hellman/RSA handshake.
- Implementing the protected record layer.
- Designing adversarial security tests.
- Debugging and checking implementation behavior.


A copy/export of the relevant conversation is included with the submission as the AI conversation log.
https://chatgpt.com/share/6ac158ce-60ec-83e9-9f91-335e478f8302
https://chatgpt.com/share/6ac16c52-6f20-83ea-9b8f-0a3ddaf9de98


## What I Used

I used AI assistance to help understand the required cryptographic construction, identify implementation details that needed to be included, write and revise portions of the Python implementation, design security tests, and organize the project documentation.

The implementation uses the Python `cryptography` library for RSA, Diffie-Hellman, AES, SHA-256, and HMAC operations rather than implementing these primitives from scratch.

## What I Changed

I reviewed the suggested implementation and adapted it to the assignment requirements and the files in my homework directory.

I specifically checked and modified the implementation to ensure that:

- The required `ffdhe3072` group is used.
- The handshake uses fresh DH keys and 16-byte nonces.
- The transcript is length-prefixed and includes the required protocol, group, identities, DH public values, and nonces.
- RSA-PSS signatures are verified against the transcript.
- Separate encryption and MAC keys are derived for each communication direction.
- The record header is authenticated.
- The record IV is constructed from the session identifier and sequence number.
- MAC verification occurs before decryption.
- Incorrect direction and unexpected sequence numbers are rejected.
- The required security tests are placed under the `tests/` directory.

## How I Tested It

I independently ran the implementation in the course VM.

The environment was checked using the required Python, OpenSSL, and package-version commands.

The generated Diffie-Hellman parameters were verified as:

- 3072-bit DH parameters
- `ffdhe3072` group

The implementation was syntax-checked using Python's `py_compile`.

The handshake was run successfully and its rejection cases were exercised, including modified nonces, modified DH public values, invalid RSA-PSS signatures, unexpected identities, malformed transcripts, and reflected handshake messages.

The secure record implementation was tested with valid bidirectional messages and adversarial records, including modified ciphertext, modified authenticated headers, replay, and wrong-direction/reflected records.

Finally, the automated pytest suite was executed: 8 PASSED
The tests were run independently in the homework virtual environment.

## Example AI Error / Limitation / Rejected Suggestion

During development, an initial version of the automated modified-header test changed the sequence-number field. Although the record was rejected, that test could be rejected because the sequence number was unexpected rather than because the header authentication failed.

I changed the test so that it modifies the message-type field while keeping the expected sequence number valid. This causes the record to reach HMAC verification and provides a more direct test that the authenticated header is protected by the MAC.

I also independently ran the resulting test suite and verified that all eight automated tests passed.

## Verification Statement

AI assistance was used as a development and learning aid. I reviewed the implementation, ran the commands and tests in the course VM, and verified the resulting behavior independently before preparing the submission.
