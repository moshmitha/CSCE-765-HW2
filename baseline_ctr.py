from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, original, modified):
    if len(original) != len(modified):
        raise ValueError("Original and modified messages must have equal length")

    delta = bytes(a ^ b for a, b in zip(original, modified))
    modified_ciphertext = bytes(
        c ^ d for c, d in zip(ciphertext, delta)
    )

    return delta, modified_ciphertext


def main():
    key = os.urandom(32)
    iv = os.urandom(16)

    original = b'{"action":"READ","path":"notes.txt"}'
    modified = b'{"action":"LIST","path":"notes.txt"}'

    print("Original plaintext:")
    print(original.decode())

    print("\nModified plaintext:")
    print(modified.decode())

    print("\nEqual length:")
    print(len(original) == len(modified))

    ciphertext = encrypt(key, iv, original)

    print("\nCiphertext:")
    print(ciphertext.hex())

    delta, modified_ciphertext = relay_modify(
        ciphertext,
        original,
        modified,
    )

    print("\nXOR delta:")
    print(delta.hex())

    print("\nModified ciphertext:")
    print(modified_ciphertext.hex())

    recovered_original = decrypt(key, iv, ciphertext)
    recovered_modified = decrypt(key, iv, modified_ciphertext)

    print("\nReceiver decrypts original ciphertext as:")
    print(recovered_original.decode())

    print("\nReceiver decrypts modified ciphertext as:")
    print(recovered_modified.decode())

    print("\nReplay demonstration:")
    replay_1 = decrypt(key, iv, ciphertext)
    replay_2 = decrypt(key, iv, ciphertext)

    print("First processing:")
    print(replay_1.decode())

    print("Second processing:")
    print(replay_2.decode())

    print("\nSame ciphertext replayed successfully:")
    print(replay_1 == replay_2)


if __name__ == "__main__":
    main()
