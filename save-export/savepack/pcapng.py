"""pcapng 读取器：解析 IDB/linktype，支持大小端和坏块重同步。

为什么不复用老的 `live._blocks`：它只认小端、不读 IDB（linktype 直接丢弃）、
遇到任何异常块长度就 `return`（一个坏块毁掉后面全部包）。

这两点在 pktmon 场景下都是致命的：pktmon 默认抓**所有网络组件**，
同一个包会在 NDIS/TCPIP 等多层被重复记录，而且**每层的帧格式不一样**
（NDIS 层是 Ethernet，TCPIP 层可能是裸 IP）。不按 linktype 解析就会把
裸 IP 当成 Ethernet 头，`pkt[12:14]` 永远不等于 0x0800，一个包都命中不了。
"""
from __future__ import annotations

from pathlib import Path

from .contract import PackError

# pcapng 块类型
SHB = 0x0A0D0D0A          # Section Header Block（字节序列固定 0a 0d 0d 0a）
IDB = 1                   # Interface Description Block
SPB = 3                   # Simple Packet Block
EPB = 6                   # Enhanced Packet Block

MAX_BLOCK = 0x4000000     # 单块 64 MiB 上限，超过视为损坏

# libpcap linktype 编号
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    LINKTYPE_NULL: "NULL/loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "raw IP",
    LINKTYPE_LINUX_SLL: "Linux SLL",
    LINKTYPE_IPV4: "IPv4",
    LINKTYPE_IPV6: "IPv6",
    LINKTYPE_LINUX_SLL2: "Linux SLL2",
}


def linktype_name(linktype: int) -> str:
    return LINKTYPE_NAMES.get(linktype, "未知(%d)" % linktype)


class Interface:
    __slots__ = ("linktype", "snaplen")

    def __init__(self, linktype: int, snaplen: int):
        self.linktype = linktype
        self.snaplen = snaplen

    def __repr__(self) -> str:
        return "linktype=%d(%s) snaplen=%d" % (
            self.linktype, linktype_name(self.linktype), self.snaplen)


class Packet:
    __slots__ = ("index", "ifid", "linktype", "data")

    def __init__(self, index: int, ifid: int, linktype: int, data: bytes):
        self.index = index
        self.ifid = ifid
        self.linktype = linktype
        self.data = data


class Reader:
    """按块流读 pcapng，逐包 yield。

    统计放在实例属性上（`byte_order` / `sections` / `block_total` /
    `block_bad` / `interfaces`），失败时用 `diagnose()` 打出来。
    """

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_file():
            raise PackError("抓包文件不存在：%s" % self.path)
        self.byte_order = None
        self.interfaces: list[Interface] = []
        self.sections = 0
        self.block_total = 0
        self.block_bad = 0
        self._index = 0

    # ------------------------------------------------------------ 内部
    def _u(self, raw: bytes) -> int:
        return int.from_bytes(raw, self.byte_order or "little")

    def _packet(self, ifid: int, data: bytes) -> Packet:
        linktype = LINKTYPE_ETHERNET
        if 0 <= ifid < len(self.interfaces):
            linktype = self.interfaces[ifid].linktype
        self._index += 1
        return Packet(self._index, ifid, linktype, data)

    # ------------------------------------------------------------ 主循环
    def packets(self):
        with open(self.path, "rb") as f:
            while True:
                pos = f.tell()
                head = f.read(12)
                if len(head) < 12:
                    return

                if head[0:4] == b"\x0a\x0d\x0d\x0a":
                    # 新 section：BOM 决定整个 section 的字节序
                    bom = head[8:12]
                    if bom == b"\x4d\x3c\x2b\x1a":
                        self.byte_order = "little"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        self.byte_order = "big"
                    else:
                        self.block_bad += 1
                        f.seek(pos + 4)
                        continue
                    blen = self._u(head[4:8])
                    if blen < 28 or blen > MAX_BLOCK:
                        self.block_bad += 1
                        f.seek(pos + 4)
                        continue
                    self.sections += 1
                    self.interfaces = []
                    self.block_total += 1
                    f.seek(pos + blen)
                    continue

                if self.byte_order is None:
                    # 文件头不是 SHB：不是 pcapng（或前面有垃圾），4 字节对齐找 SHB
                    self.block_bad += 1
                    f.seek(pos + 4)
                    continue

                btype = self._u(head[0:4])
                blen = self._u(head[4:8])
                if blen < 12 or blen > MAX_BLOCK:
                    self.block_bad += 1
                    f.seek(pos + 4)          # 重同步，不再整体放弃
                    continue

                body_len = blen - 12
                body = head[8:12][:body_len]
                rest_len = body_len - len(body)
                if rest_len > 0:
                    rest = f.read(rest_len)
                    if len(rest) < rest_len:
                        return
                    body += rest
                f.seek(pos + blen)           # 跳过尾部 total length
                self.block_total += 1

                if btype == IDB and len(body) >= 8:
                    self.interfaces.append(Interface(
                        self._u(body[0:2]), self._u(body[4:8])))
                elif btype == EPB and len(body) >= 20:
                    ifid = self._u(body[0:4])
                    caplen = self._u(body[12:16])
                    yield self._packet(ifid, body[20:20 + caplen])
                elif btype == SPB and len(body) >= 4:
                    snaplen = (self.interfaces[0].snaplen
                               if self.interfaces else 0)
                    data = body[4:]
                    if snaplen and len(data) > snaplen:
                        data = data[:snaplen]
                    yield self._packet(0, data)
                # 其他块（NRB/ISB/自定义）跳过即可

    # ------------------------------------------------------------ 诊断
    def summary(self) -> str:
        order = {"little": "小端", "big": "大端"}.get(self.byte_order, "未识别")
        return ("%s，%d 个 section，%d 个块（损坏 %d），%d 个接口"
                % (order, self.sections, self.block_total,
                   self.block_bad, len(self.interfaces)))

    def interface_summary(self) -> str:
        if not self.interfaces:
            return "（没有 IDB，按 Ethernet 处理）"
        counts: dict[int, int] = {}
        for iface in self.interfaces:
            counts[iface.linktype] = counts.get(iface.linktype, 0) + 1
        return "，".join("%s ×%d" % (linktype_name(lt), n)
                         for lt, n in sorted(counts.items()))
