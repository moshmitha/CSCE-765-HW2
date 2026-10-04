import os

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

NONCE_SIZE = 16
DH_SIZE = 384


def load_dh_parameters():
    with open("ffdhe3072.pem", "rb") as f:
        return serialization.load_pem_parameters(f.read())


def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_rsa_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def encode_field(value):
    if not isinstance(value, bytes):
        raise TypeError("Transcript fields must be bytes")

    if len(value) > 0xFFFFFFFF:
        raise ValueError("Transcript field is too long")

    return len(value).to_bytes(4, "big") + value


def validate_nonce(nonce):
    if not isinstance(nonce, bytes):
        raise ValueError("Nonce must be bytes")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce length")


def validate_dh_public(value):
    if not isinstance(value, bytes):
        raise ValueError("DH public value must be bytes")

    if len(value) != DH_SIZE:
        raise ValueError("Invalid DH public value length")


def build_transcript(
    gateway_id,
    node_id,
    gateway_dh_public,
    node_dh_public,
    gateway_nonce,
    node_nonce,
):
    if gateway_id != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if node_id != NODE_ID:
        raise ValueError("Unexpected node identity")

    validate_dh_public(gateway_dh_public)
    validate_dh_public(node_dh_public)

    validate_nonce(gateway_nonce)
    validate_nonce(node_nonce)

    fields = [
        PROTOCOL_LABEL,
        GROUP_ID,
        gateway_id,
        node_id,
        gateway_dh_public,
        node_dh_public,
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(encode_field(field) for field in fields)


def parse_transcript(transcript):
    fields = []
    offset = 0

    for _ in range(8):
        if offset + 4 > len(transcript):
            raise ValueError("Malformed transcript length prefix")

        field_length = int.from_bytes(
            transcript[offset:offset + 4],
            "big",
        )

        offset += 4

        if offset + field_length > len(transcript):
            raise ValueError("Malformed transcript field length")

        fields.append(
            transcript[offset:offset + field_length]
        )

        offset += field_length

    if offset != len(transcript):
        raise ValueError("Unexpected trailing transcript data")

    if fields[0] != PROTOCOL_LABEL:
        raise ValueError("Unexpected protocol label")

    if fields[1] != GROUP_ID:
        raise ValueError("Unexpected DH group")

    if fields[2] != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if fields[3] != NODE_ID:
        raise ValueError("Unexpected node identity")

    validate_dh_public(fields[4])
    validate_dh_public(fields[5])

    validate_nonce(fields[6])
    validate_nonce(fields[7])

    return fields


def dh_public_bytes(public_key):
    numbers = public_key.public_numbers()

    return numbers.y.to_bytes(
        DH_SIZE,
        "big",
    )


def dh_shared_secret(private_key, peer_public_key):
    shared = private_key.exchange(peer_public_key)

    if len(shared) != DH_SIZE:
        raise ValueError("Invalid DH shared secret length")

    return shared


def transcript_hash(transcript):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(transcript)
    return digest.finalize()


def signature_message(role, transcript):
    return role + transcript_hash(transcript)


def sign_transcript(private_key, role, transcript):
    message = signature_message(
        role,
        transcript,
    )

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_transcript(
    public_key,
    expected_role,
    transcript,
    signature,
):
    message = signature_message(
        expected_role,
        transcript,
    )

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise ValueError(
            "Invalid RSA-PSS transcript signature"
        ) from exc


def sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def hmac_sha256(key, data):
    h = hmac.HMAC(
        key,
        hashes.SHA256(),
    )

    h.update(data)

    return h.finalize()


def derive_keys(
    shared_secret,
    transcript_hash_value,
):
    k_master = sha256(
        b"CSCE465-KDF-v1"
        + shared_secret
        + transcript_hash_value
    )

    k_g2n_enc = hmac_sha256(
        k_master,
        b"gateway-to-node encryption"
        + transcript_hash_value,
    )

    k_g2n_mac = hmac_sha256(
        k_master,
        b"gateway-to-node MAC"
        + transcript_hash_value,
    )

    k_n2g_enc = hmac_sha256(
        k_master,
        b"node-to-gateway encryption"
        + transcript_hash_value,
    )

    k_n2g_mac = hmac_sha256(
        k_master,
        b"node-to-gateway MAC"
        + transcript_hash_value,
    )

    session_id = hmac_sha256(
        k_master,
        b"session identifier"
        + transcript_hash_value,
    )[:8]

    return {
        "g2n_enc": k_g2n_enc,
        "g2n_mac": k_g2n_mac,
        "n2g_enc": k_n2g_enc,
        "n2g_mac": k_n2g_mac,
        "session_id": session_id,
    }


def run_handshake():
    parameters = load_dh_parameters()

    gateway_rsa = generate_rsa_signing_key()
    node_rsa = generate_rsa_signing_key()

    gateway_dh_private, gateway_dh_public = generate_dh_keypair(
        parameters
    )

    node_dh_private, node_dh_public = generate_dh_keypair(
        parameters
    )

    gateway_nonce = os.urandom(NONCE_SIZE)
    node_nonce = os.urandom(NONCE_SIZE)

    gateway_dh_bytes = dh_public_bytes(
        gateway_dh_public
    )

    node_dh_bytes = dh_public_bytes(
        node_dh_public
    )

    transcript = build_transcript(
        GATEWAY_ID,
        NODE_ID,
        gateway_dh_bytes,
        node_dh_bytes,
        gateway_nonce,
        node_nonce,
    )

    parse_transcript(transcript)

    th = transcript_hash(transcript)

    gateway_signature = sign_transcript(
        gateway_rsa,
        GATEWAY_ID,
        transcript,
    )

    node_signature = sign_transcript(
        node_rsa,
        NODE_ID,
        transcript,
    )

    verify_transcript(
        gateway_rsa.public_key(),
        GATEWAY_ID,
        transcript,
        gateway_signature,
    )

    verify_transcript(
        node_rsa.public_key(),
        NODE_ID,
        transcript,
        node_signature,
    )

    gateway_shared = dh_shared_secret(
        gateway_dh_private,
        node_dh_public,
    )

    node_shared = dh_shared_secret(
        node_dh_private,
        gateway_dh_public,
    )

    if gateway_shared != node_shared:
        raise ValueError(
            "Gateway and node derived different DH secrets"
        )

    gateway_keys = derive_keys(
        gateway_shared,
        th,
    )

    node_keys = derive_keys(
        node_shared,
        th,
    )

    if gateway_keys != node_keys:
        raise ValueError(
            "Gateway and node derived different session keys"
        )

    return {
        "transcript_hash": th,
        "gateway_keys": gateway_keys,
        "node_keys": node_keys,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
        "transcript": transcript,
        "gateway_public_key": gateway_rsa.public_key(),
        "node_public_key": node_rsa.public_key(),
    }


def test_handshake_rejections():
    result = run_handshake()

    transcript = result["transcript"]

    gateway_nonce = result["gateway_nonce"]
    node_nonce = result["node_nonce"]

    fields = parse_transcript(transcript)

    gateway_dh = fields[4]
    node_dh = fields[5]

    print()
    print("Handshake rejection tests:")

    # 1. Modified nonce
    bad_nonce = bytearray(node_nonce)
    bad_nonce[0] ^= 1

    modified_transcript = build_transcript(
        GATEWAY_ID,
        NODE_ID,
        gateway_dh,
        node_dh,
        gateway_nonce,
        bytes(bad_nonce),
    )

    try:
        verify_transcript(
            result["node_public_key"],
            NODE_ID,
            modified_transcript,
            result["node_signature"],
        )

        print("Modified nonce: FAILED")

    except ValueError:
        print("Modified nonce: REJECTED")

    # 2. Modified DH public value
    bad_dh = bytearray(node_dh)
    bad_dh[0] ^= 1

    modified_transcript = build_transcript(
        GATEWAY_ID,
        NODE_ID,
        gateway_dh,
        bytes(bad_dh),
        gateway_nonce,
        node_nonce,
    )

    try:
        verify_transcript(
            result["node_public_key"],
            NODE_ID,
            modified_transcript,
            result["node_signature"],
        )

        print("Modified DH public value: FAILED")

    except ValueError:
        print("Modified DH public value: REJECTED")

    # 3. Invalid RSA-PSS signature
    bad_signature = bytearray(
        result["node_signature"]
    )

    bad_signature[0] ^= 1

    try:
        verify_transcript(
            result["node_public_key"],
            NODE_ID,
            transcript,
            bytes(bad_signature),
        )

        print("Invalid RSA-PSS signature: FAILED")

    except ValueError:
        print("Invalid RSA-PSS signature: REJECTED")

    # 4. Unexpected identity
    try:
        build_transcript(
            GATEWAY_ID,
            b"attacker",
            gateway_dh,
            node_dh,
            gateway_nonce,
            node_nonce,
        )

        print("Unexpected identity: FAILED")

    except ValueError:
        print("Unexpected identity: REJECTED")

    # 5. Malformed transcript
    try:
        parse_transcript(
            transcript[:-1]
        )

        print("Malformed transcript: FAILED")

    except ValueError:
        print("Malformed transcript: REJECTED")

    # 6. Reflected handshake message
    try:
        verify_transcript(
            result["node_public_key"],
            GATEWAY_ID,
            transcript,
            result["node_signature"],
        )

        print("Reflected handshake message: FAILED")

    except ValueError:
        print("Reflected handshake message: REJECTED")


if __name__ == "__main__":
    result = run_handshake()

    print("Authenticated handshake: SUCCESS")
    print(
        "Transcript hash:",
        result["transcript_hash"].hex(),
    )

    print(
        "Gateway and node derived the same session keys:",
        result["gateway_keys"] == result["node_keys"],
    )

    print(
        "Session ID:",
        result["gateway_keys"]["session_id"].hex(),
    )

    print(
        "Gateway -> Node encryption key length:",
        len(result["gateway_keys"]["g2n_enc"]),
    )

    print(
        "Gateway -> Node MAC key length:",
        len(result["gateway_keys"]["g2n_mac"]),
    )

    print(
        "Node -> Gateway encryption key length:",
        len(result["gateway_keys"]["n2g_enc"]),
    )

    print(
        "Node -> Gateway MAC key length:",
        len(result["gateway_keys"]["n2g_mac"]),
    )

    test_handshake_rejections()
