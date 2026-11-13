"""命令行入口：python -m savepack <subcommand> …"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import packer
from .contract import PackError, pack_name


def _find_server_dir():
    """从当前目录向上找服务端目录（含 content/player/l1.json）。"""
    here = Path.cwd()
    for base in [here] + list(here.parents):
        for cand in (base / "server", base):
            if (cand / "content" / "player" / "l1.json").is_file():
                return cand
    return None


def _save_uid(server_dir):
    try:
        data = json.loads((server_dir / "content" / "player" / "l1.json")
                          .read_text(encoding="utf-8"))
        return str((data.get("user_info") or {}).get("id") or "0")
    except (OSError, ValueError):
        return "0"


def _default_argv():
    """不带任何参数时的默认动作：本地打包，输出到当前目录，文件名自动起。

    目标：用户只要在私服根目录敲 `python -m savepack`，就能拿到一个可以直接
    发给手机导入的 zip。
    """
    server = _find_server_dir()
    if server is None:
        raise PackError("找不到服务端目录：当前目录及上层都没有 "
                        "server/content/player/l1.json。请在私服根目录运行。")
    out = Path.cwd() / ("save-%s-%s.gfsave.zip"
                        % (_save_uid(server), time.strftime("%Y%m%d")))
    return ["pack", "--from", "local",
            "--server", str(server), "--out", str(out)]


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001  （非 tty 流可能不支持）
            pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="savepack",
        description="GF 私服 A+B 存档打包工具（包格式 save-<uid>-<yyyymmdd>.gfsave.zip）")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("pack", help="打存档包")
    p_pack.add_argument("--from", dest="src", required=True,
                        choices=["local", "snapshot", "local+b"],
                        help="B 数据来源：local=不用 B；snapshot=离线快照；local+b=live 直拉")
    p_pack.add_argument("--server", required=True, help="server 目录（A 侧文件来源）")
    p_pack.add_argument("--out", required=True, help="输出 zip 路径（契约名 "
                                                    "save-<uid>-<yyyymmdd>.gfsave.zip）")
    p_pack.add_argument("--capture", help="pcapng 抓包（--from local+b 必需）")
    p_pack.add_argument("--snapshot", help="B 离线快照：目录或 samples.json 风格文件"
                                          "（--from snapshot；缺省用 <server>/samples/samples.json）")
    p_pack.add_argument("--with-friends", action="store_true",
                        help="B 好友覆盖 data/friends.json（local 来源则直接拷 server 的）")

    p_ins = sub.add_parser("inspect", help="打印来源/uid/各文件条数字节数/校验结论")
    p_ins.add_argument("zip")
    p_ins.add_argument("--server", help="可选：附带 83 键基线校验")

    p_ver = sub.add_parser("verify", help="只校验（退出码 0/1）")
    p_ver.add_argument("zip")
    p_ver.add_argument("--server", help="可选：附带 83 键基线校验")

    p_unp = sub.add_parser("unpack", help="解包到目录")
    p_unp.add_argument("zip")
    p_unp.add_argument("--to", required=True)

    return p


def _print_report(rep: dict, verbose: bool) -> bool:
    """check_pack 的 report → 控制台输出；返回 ok。"""
    meta = rep.get("meta") or {}
    if verbose:
        print("包:    %s" % rep.get("pack"))
        print("来源:  %s    uid: %s    打包: %s"
              % (meta.get("source"), meta.get("uid"), meta.get("created_utc")))
        print("合并:  used=%s b_uid=%s applied=%s"
              % (meta.get("merge", {}).get("used"),
                 meta.get("merge", {}).get("b_uid"),
                 ",".join(meta.get("merge", {}).get("applied") or []) or "-"))
        print("-" * 72)
        files = meta.get("files") or {}
        for name in sorted(files):
            info = files[name]
            print("  %-46s %6s 条 %9d B  %s…  %s"
                  % (name, info.get("count") if info.get("count") is not None else "-",
                     info.get("bytes") or 0,
                     (info.get("sha256") or "")[:12], info.get("origin")))
        print("-" * 72)
    for e in rep.get("errors") or []:
        print("  [FAIL] %s" % e)
    for w in rep.get("warnings") or []:
        print("  [WARN] %s" % w)
    ok = not rep.get("errors")
    print("校验结论: %s（错误 %d，告警 %d）"
          % ("PASS" if ok else "FAIL", len(rep.get("errors") or []),
             len(rep.get("warnings") or [])))
    return ok


def main(argv=None) -> int:
    _utf8_stdio()
    raw = list(sys.argv[1:] if argv is None else argv)
    known = {"pack", "inspect", "verify", "unpack"}
    if not raw or raw[0] not in known:
        try:
            raw = _default_argv() + raw
        except PackError as exc:
            print("[savepack] %s" % exc, file=sys.stderr)
            return 1
    args = build_parser().parse_args(raw)
    try:
        if args.cmd == "pack":
            meta = packer.build_pack(
                args.server, args.out, args.src,
                capture=args.capture, snapshot=args.snapshot,
                with_friends=args.with_friends)
            print("已打包 %s" % args.out)
            print("  来源=%s uid=%s 文件=%d 字节=%d"
                  % (meta["source"], meta["uid"], meta["file_count"],
                     meta["total_bytes"]))
            for rel, info in sorted(meta["files"].items()):
                print("  %-46s %6s 条 %9d B  %s"
                      % (rel, info["count"] if info["count"] is not None else "-",
                         info["bytes"], info["origin"]))
            for w in meta["validate"]["warnings"]:
                print("  [WARN] %s" % w)
            print("  契约名参考：%s" % pack_name(meta["uid"]))
            print()
            print("下一步：把这个 zip 发到手机（微信 / QQ / 数据线都行），")
            print("在「GF 私服」App 里点「导入存档」选中它，再点「启动」。")
            return 0

        if args.cmd == "verify":
            ok, rep = packer.check_pack(args.zip, server_dir=args.server)
            _print_report(rep, verbose=False)
            return 0 if ok else 1

        if args.cmd == "inspect":
            ok, rep = packer.check_pack(args.zip, server_dir=args.server)
            _print_report(rep, verbose=True)
            return 0 if ok else 1

        if args.cmd == "unpack":
            res = packer.unpack_pack(args.zip, args.to)
            print("已解包 %d 个文件到 %s（uid=%s）"
                  % (len(res["files"]), res["to"], res["uid"]))
            for name in res["files"]:
                print("  %s" % name)
            return 0

        print("未知子命令：%s" % args.cmd, file=sys.stderr)  # pragma: no cover
        return 2
    except PackError as exc:
        print("[savepack] %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("[savepack] 文件操作失败：%s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
