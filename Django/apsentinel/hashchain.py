import hashlib

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def compute_payload_hash(canonical_json_bytes: bytes) -> bytes:
    return sha256_bytes(canonical_json_bytes)

def compute_chain_hash(prev_chain_hash: bytes | None, payload_hash: bytes, server_ts_iso: str) -> bytes:
    """
    Deterministic chain:
    SHA256( prev(32 bytes) || payload_hash || server_ts_iso )
    """
    if prev_chain_hash is None:
        # first link in chain → use 32 zero bytes
        prev_chain_hash = b"\x00" * 32
    data = prev_chain_hash + payload_hash + server_ts_iso.encode("utf-8")
    return sha256_bytes(data)
