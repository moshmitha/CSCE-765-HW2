from handshake import run_handshake, verify_transcript


def test_valid_handshake():
    result = run_handshake()

    assert result["gateway_keys"] == result["node_keys"]
    assert len(result["transcript_hash"]) == 32
    assert len(result["gateway_keys"]["session_id"]) == 8


def test_invalid_rsa_pss_signature_rejected():
    result = run_handshake()

    bad_signature = bytearray(result["node_signature"])
    bad_signature[0] ^= 1

    try:
        verify_transcript(
            result["node_public_key"],
            b"node",
            result["transcript"],
            bytes(bad_signature),
        )
        assert False, "Invalid RSA-PSS signature was accepted"
    except ValueError:
        pass


def test_reflected_handshake_message_rejected():
    result = run_handshake()

    try:
        verify_transcript(
            result["node_public_key"],
            b"gateway",
            result["transcript"],
            result["node_signature"],
        )
        assert False, "Reflected handshake message was accepted"
    except ValueError:
        pass
