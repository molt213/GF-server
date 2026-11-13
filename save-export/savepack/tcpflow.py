"""链路层 → IP → TCP → 按连接重组字节流 → HTTP/1.x 消息。

解决三个现实问题（老实现全部踩中）：

1. **pktmon 抓所有组件**，同一个包会在多层重复记录 → 重组时按 seq 覆盖去重；
2. **不同组件帧格式不同**（NDIS 层 Ethernet、TCPIP 层裸 IP）→ 按 pcapng 的
   IDB linktype 解析，不硬编码 14 字节头；
3. **HTTP 头体经常跨 TCP 段** → 先重组字节流，再在流里找消息起点，
   不要求消息从某个段的第一字节开始。
"""
from __future__ import annotations

import gzip
import re

from . import pcapng as _pcapng

_ETH_VLAN = (0x8100, 0x88A8, 0x9100)
_ETH_IPV4 = 0x0800

_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
            b"OPTIONS ", b"PATCH ")
_HTTP_VER = b"HTTP/1."


# ---------------------------------------------------------------- 链路层
def ip_packet(frame: bytes, linktype: int):
    """剥链路层头，返回 (ip_version, raw_ip) 或 None。"""
    if not frame:
        return None

    if linktype == _pcapng.LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        off = 12
        ethertype = int.from_bytes(frame[off:off + 2], "big")
        off += 2
        # 最多剥两层 VLAN/QinQ
        for _ in range(2):
            if ethertype not in _ETH_VLAN:
                break
            if len(frame) < off + 4:
                return None
            ethertype = int.from_bytes(frame[off + 2:off + 4], "big")
            off += 4
        if ethertype != _ETH_IPV4:
            return None
        return 4, frame[off:]

    if linktype in (_pcapng.LINKTYPE_RAW,
                    _pcapng.LINKTYPE_IPV4,
                    _pcapng.LINKTYPE_IPV6):
        ver = frame[0] >> 4
        return (ver, frame) if ver in (4, 6) else None

    if linktype == _pcapng.LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        proto = int.from_bytes(frame[14:16], "big")
        return (4, frame[16:]) if proto == _ETH_IPV4 else None

    if linktype == _pcapng.LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        proto = int.from_bytes(frame[0:2], "big")
        return (4, frame[20:]) if proto == _ETH_IPV4 else None

    if linktype == _pcapng.LINKTYPE_NULL:
        if len(frame) < 4:
            return None
        # BSD loopback：首 4 字节是地址族，主机序（小端 2 = IPv4）
        family = int.from_bytes(frame[0:4], "little")
        if family == 2:
            return 4, frame[4:]
        if family in (24, 28, 30, 10):
            return 6, frame[4:]
        return None

    # 未知 linktype：按首字节版本号猜一下，总比全丢强
    ver = frame[0] >> 4
    return (ver, frame) if ver in (4, 6) else None


def ip_payload(raw: bytes):
    """解 IP 头，返回 (src, dst, proto, payload, truncated) 或 None。"""
    if not raw:
        return None
    ver = raw[0] >> 4

    if ver == 4:
        if len(raw) < 20:
            return None
        ihl = (raw[0] & 0x0F) * 4
        if ihl < 20 or len(raw) < ihl:
            return None
        total = int.from_bytes(raw[2:4], "big") or len(raw)
        proto = raw[9]
        src = ".".join(str(b) for b in raw[12:16])
        dst = ".".join(str(b) for b in raw[16:20])
        frag = int.from_bytes(raw[6:8], "big")
        offset = (frag & 0x1FFF) * 8
        if offset:
            return None                      # 非首片：没有 TCP 头
        truncated = bool(frag & 0x2000)      # MF：后面还有分片
        return src, dst, proto, raw[ihl:total], truncated

    if ver == 6:
        if len(raw) < 40:
            return None
        proto = raw[6]
        plen = int.from_bytes(raw[4:6], "big") or (len(raw) - 40)
        src = _ipv6(raw[8:24])
        dst = _ipv6(raw[24:40])
        return src, dst, proto, raw[40:40 + plen], False

    return None


def _ipv6(raw: bytes) -> str:
    return ":".join("%x" % int.from_bytes(raw[i:i + 2], "big")
                    for i in range(0, 16, 2))


def tcp_segment(payload: bytes):
    """返回 (sport, dport, seq, flags, tcp_payload) 或 None。"""
    if len(payload) < 20:
        return None
    sport = int.from_bytes(payload[0:2], "big")
    dport = int.from_bytes(payload[2:4], "big")
    seq = int.from_bytes(payload[4:8], "big")
    doff = (payload[12] >> 4) * 4
    if doff < 20 or doff > len(payload):
        return None
    return sport, dport, seq, payload[13], payload[doff:]


# ---------------------------------------------------------------- 重组
class Direction:
    """一个方向的字节流：按 seq 排序，重叠覆盖，遇到缺口切成多个 run。"""

    __slots__ = ("segments", "segment_count")

    def __init__(self):
        self.segments: list[tuple[int, bytes]] = []
        self.segment_count = 0

    def add(self, seq: int, data: bytes) -> None:
        if data:
            self.segments.append((seq, data))
            self.segment_count += 1

    def runs(self) -> list[tuple[int, bytes]]:
        """返回 [(起始 seq, 连续字节)]，不跨缺口拼接（跨缺口会拼出假数据）。"""
        if not self.segments:
            return []
        segs = sorted(self.segments, key=lambda item: item[0])
        out: list[tuple[int, bytes]] = []
        base = segs[0][0]
        buf = bytearray(segs[0][1])
        end = base + len(buf)
        for seq, data in segs[1:]:
            if seq > end:                     # 有缺口
                out.append((base, bytes(buf)))
                base, buf, end = seq, bytearray(data), seq + len(data)
                continue
            if seq + len(data) <= end:
                continue                      # 完全重复（pktmon 多组件）
            buf += data[end - seq:]
            end = seq + len(data)
        out.append((base, bytes(buf)))
        return out

    def buffer(self) -> bytes:
        """只用于「单 run」的常见情况；有缺口时返回第一段。"""
        runs = self.runs()
        return runs[0][1] if runs else b""

    def __len__(self) -> int:
        return sum(len(data) for _seq, data in self.segments)


# ---------------------------------------------------------------- HTTP
class Message:
    __slots__ = ("kind", "method", "target", "status", "headers", "body", "seq")

    def __init__(self, kind, method, target, status, headers, body, seq):
        self.kind = kind            # "request" / "response"
        self.method = method        # 请求方法（响应为 None）
        self.target = target        # 请求路径（响应为 None）
        self.status = status        # 状态码（请求为 None）
        self.headers = headers
        self.body = body
        self.seq = seq

    def __repr__(self) -> str:
        if self.kind == "request":
            return "<request %s %s %dB>" % (self.method, self.target,
                                            len(self.body))
        return "<response %s %dB>" % (self.status, len(self.body))


def _headers(head: bytes) -> dict:
    out: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if not _:
            continue
        out[name.strip().decode("latin-1").lower()] = \
            value.strip().decode("latin-1")
    return out


def _read_chunked(buf: bytes, pos: int):
    out = bytearray()
    p = pos
    while True:
        eol = buf.find(b"\r\n", p)
        if eol < 0:
            return None, 0
        try:
            size = int(buf[p:eol].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return None, 0
        p = eol + 2
        if size == 0:
            if buf[p:p + 2] == b"\r\n":
                p += 2
            return bytes(out), p - pos
        if p + size > len(buf):
            return None, 0
        out += buf[p:p + size]
        p += size
        if buf[p:p + 2] == b"\r\n":
            p += 2


def _read_body(buf: bytes, pos: int, head: bytes):
    """返回 (body, consumed)；body 为 None 表示这个 run 里读不全。"""
    hdr = _headers(head)
    if "chunked" in hdr.get("transfer-encoding", "").lower():
        return _read_chunked(buf, pos)
    raw_len = hdr.get("content-length")
    if raw_len is None:
        return b"", 0
    try:
        length = int(raw_len)
    except ValueError:
        return b"", 0
    if length < 0:
        return b"", 0
    if pos + length > len(buf):
        return None, 0
    return buf[pos:pos + length], length


def _next_start(buf: bytes, start: int) -> int:
    """找下一个 HTTP 消息起点（必须在行首），找不到返回 -1。"""
    pos = start
    while pos < len(buf):
        cand = -1
        for marker in _METHODS:
            hit = buf.find(marker, pos)
            if hit >= 0 and (cand < 0 or hit < cand):
                cand = hit
        hit = buf.find(_HTTP_VER, pos)
        if hit >= 0 and (cand < 0 or hit < cand):
            cand = hit
        if cand < 0:
            return -1
        if cand == 0 or buf[cand - 2:cand] == b"\r\n":
            return cand
        pos = cand + 1
    return -1


def iter_messages(buf: bytes):
    """在任意字节流里找 HTTP/1.x 消息，容忍流从中间开始、也容忍前面有噪声。"""
    pos = 0
    while pos < len(buf):
        start = _next_start(buf, pos)
        if start < 0:
            return
        head_end = buf.find(b"\r\n\r\n", start)
        if head_end < 0:
            return
        head = buf[start:head_end]
        first = head.split(b"\r\n", 1)[0]
        body, consumed = _read_body(buf, head_end + 4, head)

        if body is not None:
            hdr = _headers(head)
            if first.startswith(_HTTP_VER):
                try:
                    status = int(first.split(b" ")[1])
                except (IndexError, ValueError):
                    status = 0
                yield Message("response", None, None, status, hdr, body,
                              start)
            else:
                parts = first.split(b" ")
                method = parts[0].decode("latin-1") if parts else ""
                target = parts[1].decode("latin-1") if len(parts) > 1 else ""
                yield Message("request", method, target, None, hdr, body,
                              start)
            pos = head_end + 4 + consumed
        else:
            pos = head_end + 4


def maybe_ungzip(body: bytes, headers: dict) -> bytes:
    """HTTP 层 gzip（信封自己的 gzip 由 envelope.decode 处理）。"""
    if "gzip" not in headers.get("content-encoding", "").lower():
        return body
    if body[:2] != b"\x1f\x8b":
        return body
    try:
        return gzip.decompress(body)
    except OSError:
        return body


# 供外部做粗筛用
def looks_like_envelope(body: bytes) -> bool:
    text = body.lstrip()
    return bool(text) and (text[:1] == b"#" or re.match(rb"^[A-Za-z0-9+/=\s]+$",
                                                       text[:80]) is not None)
