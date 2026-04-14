from nacl.signing import VerifyKey
import binascii

def verify_ed25519_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verifies an Ed25519 signature to prove identity without exchanging secrets."""
    try:
        vk = VerifyKey(binascii.unhexlify(public_key_hex))
        vk.verify(message, binascii.unhexlify(signature_hex))
        return True
    except Exception as e:
        print(f"Signature verify error: {e}")
        return False
