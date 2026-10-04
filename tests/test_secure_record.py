from handshake import run_handshake
from secure_record import (
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
    open_record,
    seal,
)


def test_valid_bidirectional_records():
    result = run_handshake()
    keys = result["gateway_keys"]

    gateway_message = b"hello from gateway"
    node_message = b"hello from node"

    gateway_record = seal(
        keys,
        GATEWAY_TO_NODE,
        0,
        1,
        gateway_message,
    )

    node_record = seal(
        keys,
        NODE_TO_GATEWAY,
        0,
        1,
        node_message,
    )

    assert open_record(
        keys,
        GATEWAY_TO_NODE,
        0,
        gateway_record,
    ) == gateway_message

    assert open_record(
        keys,
        NODE_TO_GATEWAY,
        0,
        node_record,
    ) == node_message


def test_modified_ciphertext_rejected():
    result = run_handshake()
    keys = result["gateway_keys"]

    record = seal(
        keys,
        GATEWAY_TO_NODE,
        0,
        1,
        b"authorized local tool call",
    )

    modified = bytearray(record)

    # Header = 15 bytes, IV = 16 bytes.
    # Therefore ciphertext begins at byte 31.
    ciphertext_index = 15 + 16
    modified[ciphertext_index] ^= 1

    try:
        open_record(
            keys,
            GATEWAY_TO_NODE,
            0,
            bytes(modified),
        )
        assert False, "Modified ciphertext was accepted"
    except ValueError:
        pass


def test_modified_authenticated_header_rejected():
    result = run_handshake()
    keys = result["gateway_keys"]

    record = seal(
        keys,
        GATEWAY_TO_NODE,
        0,
        1,
        b"authorized local tool call",
    )

    modified = bytearray(record)

    # Message type is byte 10 of the 15-byte header.
    # Changing it should cause the HMAC verification to fail.
    message_type_index = 10
    modified[message_type_index] ^= 1

    try:
        open_record(
            keys,
            GATEWAY_TO_NODE,
            0,
            bytes(modified),
        )
        assert False, "Modified authenticated header was accepted"
    except ValueError:
        pass


def test_replay_rejected():
    result = run_handshake()
    keys = result["gateway_keys"]

    record = seal(
        keys,
        GATEWAY_TO_NODE,
        0,
        1,
        b"authorized local tool call",
    )

    # First delivery is valid.
    assert open_record(
        keys,
        GATEWAY_TO_NODE,
        0,
        record,
    ) == b"authorized local tool call"

    # Receiver now expects sequence 1.
    # Replaying sequence 0 must be rejected.
    try:
        open_record(
            keys,
            GATEWAY_TO_NODE,
            1,
            record,
        )
        assert False, "Replayed record was accepted"
    except ValueError:
        pass


def test_reflected_record_rejected():
    result = run_handshake()
    keys = result["gateway_keys"]

    record = seal(
        keys,
        GATEWAY_TO_NODE,
        0,
        1,
        b"authorized local tool call",
    )

    try:
        open_record(
            keys,
            NODE_TO_GATEWAY,
            0,
            record,
        )
        assert False, "Reflected record was accepted"
    except ValueError:
        pass

