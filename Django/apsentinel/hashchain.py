import hashlib

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def compute_payload_hash(canonical_json_bytes: bytes) -> bytes:
    return sha256_bytes(canonical_json_bytes)

def compute_chain_hash(prev_chain_hash: bytes | None, payload_hash: bytes, server_ts_iso: str) -> bytes:
    # Simple, deterministic chain: SHA256( prev || payload_hash || server_ts_iso )
    prev = prev_chain_hash or b""
    return sha256_bytes(prev + payload_hash + server_ts_iso.encode("utf-8"))
