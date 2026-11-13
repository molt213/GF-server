"""AC.AuthCode 信封（Discuz authcode 变体）——客户端侧实现。

算法与 `server/gfcrypto.py` 同源。这里自带一份，是为了让打包出来的 exe
不需要旁边有 `server/` 目录。

两条路径的区别（M2 反汇编定案）：
  * 登录前的队列响应固定用 "yundoudou" 作密钥；
  * 登录后的业务响应改用会话 sign。
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import time

QUEUE_KEY = "yundoudou"


def md5_hex(value) -> str:
    """这里必须是 MD5：官方客户端 AC.AuthCode 就是这样算的。

    不是用它做安全防护，而是复刻协议——换成 SHA-256 会导致信封
    校验位对不上、一个字都解不开。扫描器报「弱哈希」属预期，勿改。
    """
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.md5(value).hexdigest()


def _ksa(key: bytes, n: int = 256):
    s = list(range(n))
    j = 0
    klen = len(key) or 1
    for i in range(n):
        j = (j + s[i] + key[i % klen]) % n
        s[i], s[j] = s[j], s[i]
    return s


def _prga(s, data: bytes) -> bytes:
    out = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data):
        i = (i + 1) % 256
        a = s[i]
        j = (j + a) % 256
        s[i], s[j] = s[j], s[i]
        out[k] = b ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def rc4(data: bytes, key) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return _prga(_ksa(key), data)


def _keys(key: str):
    md5key = md5_hex(key)
    keyb = md5_hex(md5key[16:32])
    keya = md5_hex(md5key[0:16])
    return keya, keyb + md5_hex(keyb)


def decode(source: str, key: str, now=None, grace: int = 0) -> bytes:
    """解信封，返回载荷 bytes（gzip 自动解压）。失败返回 b""。

    grace：允许的过期容差（秒）。本机时钟比官方服务器慢时给一点余量。
    """
    if now is None:
        now = int(time.time())
    if not source:
        return b""
    keya, cryptkey = _keys(key)
    try:
        raw = base64.b64decode(source + "=" * ((-len(source)) % 4))
    except (ValueError, TypeError):
        return b""
    inner = rc4(raw, cryptkey)
    if len(inner) < 26:
        return b""
    try:
        exp = int(inner[0:10])
    except ValueError:
        return b""
    if exp and exp - now < -grace:
        return b""
    if inner[10:26] != md5_hex(inner[26:] + keya.encode()).encode()[0:16]:
        return b""
    body = inner[26:]
    if body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)
        except OSError:
            return b""
    return body


def encode_bytes(body, key: str, expiry: int = 3600, now=None) -> str:
    """把 bytes 载荷封进信封，返回 base64 串（不含前导 '#'）。"""
    if now is None:
        now = int(time.time())
    if isinstance(body, str):
        body = body.encode("utf-8")
    keya, cryptkey = _keys(key)
    exp10 = str(now + expiry) if expiry else "0000000000"
    sign16 = md5_hex(body + keya.encode())[0:16]
    plain = exp10.encode() + sign16.encode() + body
    return base64.b64encode(rc4(plain, cryptkey)).decode()
