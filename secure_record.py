from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION = 1
HEADER_SIZE = 15
IV_SIZE = 16
TAG_SIZE = 32
KEY_SIZE = 32

GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1


def _get_keys(keys, direction):
    if direction == GATEWAY_TO_NODE:
        enc_key = keys["g2n_enc"]
        mac_key = keys["g2n_mac"]
    elif direction == NODE_TO_GATEWAY:
        enc_key = keys["n2g_enc"]
        mac_key = keys["n2g_mac"]
    else:
        raise ValueError("Invalid direction")

    if len(enc_key) != KEY_SIZE:
        raise ValueError("Invalid encryption key length")

    if len(mac_key) != KEY_SIZE:
        raise ValueError("Invalid MAC key length")

    return enc_key, mac_key


def _build_header(
    direction,
    sequence,
    message_type,
    ciphertext_length,
):
    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid direction")

    if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Invalid sequence number")

    if not 0 <= message_type <= 0xFF:
        raise ValueError("Invalid message type")

    if not 0 <= ciphertext_length <= 0xFFFFFFFF:
        raise ValueError("Invalid ciphertext length")

    return (
        VERSION.to_bytes(1, "big")
        + direction.to_bytes(1, "big")
        + sequence.to_bytes(8, "big")
        + message_type.to_bytes(1, "big")
        + ciphertext_length.to_bytes(4, "big")
    )


def _parse_header(header):
    if len(header) != HEADER_SIZE:
        raise ValueError("Invalid header length")

    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(
        header[2:10],
        "big",
    )
    message_type = header[10]
    ciphertext_length = int.from_bytes(
        header[11:15],
        "big",
    )

    if version != VERSION:
        raise ValueError("Unsupported record version")

    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid direction")

    return (
        version,
        direction,
        sequence,
        message_type,
        ciphertext_length,
    )


def _hmac_tag(mac_key, data):
    h = hmac.HMAC(
        mac_key,
        hashes.SHA256(),
    )
    h.update(data)
    return h.finalize()


def _encrypt(enc_key, iv, plaintext):
    cipher = Cipher(
        algorithms.AES(enc_key),
        modes.CTR(iv),
    )

    encryptor = cipher.encryptor()

    return (
        encryptor.update(plaintext)
        + encryptor.finalize()
    )


def _decrypt(enc_key, iv, ciphertext):
    cipher = Cipher(
        algorithms.AES(enc_key),
        modes.CTR(iv),
    )

    decryptor = cipher.decryptor()

    return (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )


def seal(
    keys,
    direction,
    sequence,
    message_type,
    plaintext,
):
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    session_id = keys["session_id"]

    if not isinstance(session_id, bytes):
        raise TypeError("Session ID must be bytes")

    if len(session_id) != 8:
        raise ValueError("Session ID must be 8 bytes")

    enc_key, mac_key = _get_keys(
        keys,
        direction,
    )

    header = _build_header(
        direction,
        sequence,
        message_type,
        len(plaintext),
    )

    iv = (
        session_id
        + sequence.to_bytes(8, "big")
    )

    ciphertext = _encrypt(
        enc_key,
        iv,
        plaintext,
    )

    tag = _hmac_tag(
        mac_key,
        header + iv + ciphertext,
    )

    return header + iv + ciphertext + tag


def open_record(
    keys,
    expected_direction,
    expected_sequence,
    record,
):
    if not isinstance(record, bytes):
        raise TypeError("Record must be bytes")

    if not 0 <= expected_sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Invalid expected sequence number")

    if len(record) < HEADER_SIZE + IV_SIZE + TAG_SIZE:
        raise ValueError("Record is too short")

    header = record[:HEADER_SIZE]

    (
        version,
        direction,
        sequence,
        message_type,
        ciphertext_length,
    ) = _parse_header(header)

    if direction != expected_direction:
        raise ValueError("Wrong record direction")

    if sequence != expected_sequence:
        raise ValueError("Unexpected sequence number")

    expected_record_length = (
        HEADER_SIZE
        + IV_SIZE
        + ciphertext_length
        + TAG_SIZE
    )

    if len(record) != expected_record_length:
        raise ValueError("Invalid record length")

    iv_start = HEADER_SIZE
    iv_end = iv_start + IV_SIZE

    iv = record[iv_start:iv_end]

    ciphertext_start = iv_end
    ciphertext_end = (
        ciphertext_start + ciphertext_length
    )

    ciphertext = record[
        ciphertext_start:ciphertext_end
    ]

    tag = record[ciphertext_end:]

    session_id = keys["session_id"]

    if len(session_id) != 8:
        raise ValueError("Session ID must be 8 bytes")

    expected_iv = (
        session_id
        + sequence.to_bytes(8, "big")
    )

    if iv != expected_iv:
        raise ValueError("Invalid IV")

    enc_key, mac_key = _get_keys(
        keys,
        direction,
    )

    authenticated_data = (
        header
        + iv
        + ciphertext
    )


    verifier = hmac.HMAC(
        mac_key,
        hashes.SHA256(),
    )
    verifier.update(authenticated_data)

    try:
        verifier.verify(tag)
    except Exception as exc:
        raise ValueError("Invalid record MAC") from exc

    plaintext = _decrypt(
        enc_key,
        iv,
        ciphertext,
    )

    return plaintext
