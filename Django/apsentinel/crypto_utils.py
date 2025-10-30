import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def verify_ecdsa_p256_sha256(pubkey_pem: str, message: bytes, signature_b64: str) -> bool:
    """
    Verify ECDSA P-256 / SHA-256 signature. Signature must be DER-encoded, Base64 string.
    """
    public_key = serialization.load_pem_public_key(pubkey_pem.encode("utf-8"))
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
