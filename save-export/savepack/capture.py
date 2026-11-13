"""pktmon 抓包：不改 hosts、不占端口。

用 Windows 自带的 pktmon 抓一小段网卡流量，登录过程结束后转成 pcapng。

两个关键点：

* **加 filter 只抓网关 80 端口**。pktmon 默认 `--comp all` 会抓所有网络组件，
  同一个包在多层重复记录，一次登录能抓出几十 MB 无关流量；按「网关 IP + TCP +
  80 端口」过滤后通常只剩几百 KB，全是登录相关的包。
* **失败不删抓包**。`cleanup(keep=True)` 保留 pcapng 并返回路径，这样解析失败
  时还能离线复现（`--from-pcap`），不用让用户重新登录。
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .contract import PackError

PKTMON = "pktmon.exe"
FILTER_PREFIX = "GFSAVEPACK"
MAX_FILTERS = 8


def _run(args, timeout: int = 120):
    try:
        return subprocess.run([PKTMON] + args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise PackError("找不到 pktmon.exe（需要 Windows 10 1809+）") from exc
    except subprocess.TimeoutExpired as exc:
        raise PackError("pktmon 超时：%s" % exc) from exc


def _quiet(args, timeout: int = 30):
    """清理类命令：失败不抛错。"""
    try:
        return _run(args, timeout=timeout)
    except PackError:
        return None


def _text(result) -> str:
    if result is None:
        return ""
    return ((result.stdout or "") + (result.stderr or "")).strip()


def clear_filters() -> None:
    """删掉本工具留下的过滤器。只按自己的名字删，不动别人的。"""
    for i in range(MAX_FILTERS):
        _quiet(["filter", "remove", FILTER_PREFIX + str(i)])
    _quiet(["filter", "remove", FILTER_PREFIX])


class Capture:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="gfcapture-"))
        self.etl = self.dir / "cap.etl"
        self.pcapng = self.dir / "cap.pcapng"
        self.started = False
        self.filter_names: list[str] = []
        self.filter_note = ""

    # ------------------------------------------------------------ 抓包
    def start(self, ips=None, use_filter: bool = True) -> None:
        """开始抓包。

        ips 为空时只按 **TCP 80 端口**过滤、不限 IP —— 官方有多个服
        （M4 / iOS / 渠道服…），网关域名各不相同，列不全也锁不准；
        先按端口抓下来，再从请求的 Host 头认服务器。
        """
        self.filter_names = []
        self.filter_note = ""
        if use_filter:
            clear_filters()
            if ips:
                rules = [(FILTER_PREFIX + str(i), ["-i", str(ip)])
                         for i, ip in enumerate(ips[:MAX_FILTERS])]
            else:
                rules = [(FILTER_PREFIX + "0", [])]
            for name, extra in rules:
                r = _quiet(["filter", "add", name] + extra
                           + ["-t", "TCP", "-p", "80"])
                if r is not None and r.returncode == 0:
                    self.filter_names.append(name)
                else:
                    self.filter_note = ("过滤器加不上（%s），本次全量抓包"
                                        % _text(r)[:120])
                    break

        r = _run(["start", "--capture", "--pkt-size", "0",
                  "-f", str(self.etl)])
        text = _text(r).strip()
        if r.returncode != 0 or "错误" in text:
            clear_filters()
            raise PackError("pktmon 启动失败：%s" % text[:300])
        self.started = True

    def stop(self) -> Path:
        """停止抓包并转成 pcapng，返回 pcapng 路径。"""
        if not self.started:
            raise PackError("抓包还没启动")
        _run(["stop"], timeout=90)
        self.started = False
        clear_filters()
        if not self.etl.is_file():
            raise PackError("pktmon 没有生成抓包文件（是不是启动后就立刻停了？）")
        size = self.etl.stat().st_size
        if size < 1024:
            raise PackError(
                "抓到的数据太少（%d 字节）。\n"
                "  如果开了过滤器，说明游戏没走这个 IP —— 加 --no-filter 重抓。"
                % size)
        r = _run(["etl2pcap", str(self.etl), "--out", str(self.pcapng)],
                 timeout=300)
        if not self.pcapng.is_file() or self.pcapng.stat().st_size == 0:
            raise PackError("etl 转 pcapng 失败：%s" % _text(r)[:300])
        return self.pcapng

    # ------------------------------------------------------------ 收尾
    def cleanup(self, keep: bool = False):
        """清理。keep=True 时保留 pcapng 并返回路径（失败现场）。"""
        if self.started:
            try:
                _run(["stop"], timeout=30)
            except PackError:
                pass
            self.started = False
        clear_filters()
        if keep and self.pcapng.is_file():
            return self.pcapng
        shutil.rmtree(self.dir, ignore_errors=True)
        return None

    def status_text(self) -> str:
        if self.filter_names:
            return "只抓网关 80 端口（%d 个过滤器）" % len(self.filter_names)
        if self.filter_note:
            return self.filter_note
        return "全量抓包（没加过滤器）"
