"""一键打包存档：给「打包存档.bat」用的入口。

在电脑上找到私服服务端的用户数据（server/content/player/l1.json），
打成可以直接传到手机导入的 save-<uid>-<日期>.gfsave.zip。
不联网、不连手机、不需要 adb。

用法（在 tools 目录）：
    python -m savepack.auto
    python -m savepack.auto --out-dir D:\\某处
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import cli
from .contract import PACK_FILES, PackError, pack_name


def project_root() -> Path:
    """私服根目录。

    - 源码运行：tools/savepack/auto.py → 向上三层
    - 打包成 exe：__file__ 指向 PyInstaller 的临时解压目录，不能用；
      必须用 exe 自己所在的位置（exe 就放在私服根目录）。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def find_server(explicit: str = ""):
    """找服务端数据目录。

    顺序：显式指定 → 脚本所在私服目录（及其上层）→ 当前目录（及其上层）。
    判据只有一个：存在 content/player/l1.json。
    """
    if explicit:
        p = Path(explicit).expanduser().resolve()
        for cand in (p, p / "server"):
            if (cand / "content" / "player" / "l1.json").is_file():
                return cand
        raise PackError("指定的目录里没有 content/player/l1.json：%s" % p)

    seen = set()
    for start in (project_root(), Path.cwd()):
        for base in [start] + list(start.parents):
            for cand in (base / "server", base):
                key = str(cand)
                if key in seen:
                    continue
                seen.add(key)
                if (cand / "content" / "player" / "l1.json").is_file():
                    return cand
    return None


def _prepare_out(out: Path) -> Path:
    """固定用契约名：同一天重跑就覆盖上一次的包，不堆一堆副本。

    不覆盖会让 cli 的契约名校验告警，而手机端只按 save-<uid>-<yyyymmdd> 认。
    """
    if out.exists():
        print("（同名旧包已存在，直接覆盖：%s）" % out.name)
        try:
            out.unlink()
        except OSError as exc:
            raise PackError("旧包删不掉：%s（%s）" % (out, exc))
    return out


def _raw_size(source: Path) -> int:
    """8 条契约文件未压缩的总字节数。"""
    total = 0
    for rel in PACK_FILES:
        p = source / rel
        if p.is_file():
            total += p.stat().st_size
    return total


def _human(n: int) -> str:
    if n >= 1048576:
        return "%.1f MB" % (n / 1048576.0)
    if n >= 1024:
        return "%.0f KB" % (n / 1024.0)
    return "%d B" % n


def _open_in_explorer(path: Path) -> None:
    if os.name != "nt":
        return
    try:
        subprocess.Popen(["explorer", "/select,%s" % path])
    except OSError:
        pass


def main(argv=None) -> int:
    cli._utf8_stdio()
    p = argparse.ArgumentParser(
        prog="savepack.auto",
        description="一键打包存档：自动找服务端用户数据并打成 gfsave.zip")
    p.add_argument("--server", default="",
                   help="指定服务端数据目录（默认自动找）")
    p.add_argument("--out-dir", help="输出目录（默认私服根目录）")
    p.add_argument("--no-open", action="store_true",
                   help="打完不打开资源管理器")
    args = p.parse_args(argv)

    out_dir = (Path(args.out_dir).expanduser().resolve()
               if args.out_dir else project_root())
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("[savepack] 输出目录不可用：%s（%s）" % (out_dir, exc))
        return 1

    try:
        source = find_server(args.server)
    except PackError as exc:
        print("[savepack] %s" % exc)
        return 1

    if source is None:
        print("没有找到服务端的用户数据（content/player/l1.json）。")
        print()
        print("这个程序要放在私服目录里用，旁边应该有 server 目录：")
        print()
        print("  私服目录\\")
        print("    server\\content\\player\\l1.json      <- 用户数据")
        print("    打包存档.exe                        <- 本程序")
        print()
        print("如果数据在别处，也可以带参数指定：")
        print("  打包存档.exe --server D:\\某个\\server")
        return 1

    print("数据源：%s" % source)
    uid = cli._save_uid(source)
    out = _prepare_out(out_dir / pack_name(uid))
    print("打包中…  uid=%s" % uid)

    rc = cli.main(["pack", "--from", "local",
                   "--server", str(source), "--out", str(out)])
    if rc != 0:
        print()
        print("打包失败（退出码 %d）。" % rc)
        return rc

    print()
    print("完成：%s" % out)
    print("  文件大小 %s（原始数据 %s，zip 压缩后）"
          % (_human(out.stat().st_size), _human(_raw_size(source))))
    if not args.no_open:
        _open_in_explorer(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
