"""规范序列化、哈希与 Ed25519 签名。所有签名对象先经 canonical() 序列化。"""
from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj) -> bytes:
    """确定性 JSON：键排序、无多余空白、UTF-8。签名与哈希的唯一序列化方式。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def h(obj) -> str:
    """对象的内容哈希（blake2b-128，十六进制）。用于 token_id / receipt_id。"""
    return hashlib.blake2b(canonical(obj), digest_size=16).hexdigest()


def hbytes(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=16).hexdigest()


# --- 密钥 ---------------------------------------------------------------

def new_keypair() -> tuple[bytes, bytes]:
    """返回 (私钥原始 32 字节, 公钥原始 32 字节)。"""
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def pub_of(sk_raw: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(sk_raw).public_key().public_bytes_raw()


def sign(sk_raw: bytes, obj) -> str:
    STATS["sign"] += 1
    STATS["sign_bytes"] += len(canonical(obj))
    sk = Ed25519PrivateKey.from_private_bytes(sk_raw)
    return sk.sign(canonical(obj)).hex()


def verify(pk_hex: str, obj, sig_hex: str) -> bool:
    STATS["verify"] += 1
    STATS["verify_bytes"] += len(canonical(obj))
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        pk.verify(bytes.fromhex(sig_hex), canonical(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- 成本计量 -----------------------------------------------------------
STATS = {"sign": 0, "verify": 0, "sign_bytes": 0, "verify_bytes": 0}


def reset_stats() -> None:
    for k in STATS:
        STATS[k] = 0
