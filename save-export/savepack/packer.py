"""打包、校验、解包。

打包流程：
  A 文件（server 目录，存在才拷；l1 必需）→ normalize（uid 键位对齐）
  → B 数据（按 --from：无 / 快照 / live 直拉）merge → validate（83 键基线）
  → 逐文件 sha256/计数写 meta.json → 打 zip（契约路径）。

未被改写的文件保持源字节（local 模式整包与 server 目录逐字节一致）；
被 normalize/merge 改写的文件用 canonical_json_bytes 确定性重写。
"""
from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import merge as merge_mod
from . import normalize as normalize_mod
from . import snapshot as snapshot_mod
from . import validate as validate_mod
from .contract import (
    EXTRA_ALLOWED,
    L1_PATH,
    META_NAME,
    PACK_FILES,
    PackError,
    canonical_json_bytes,
    count_of,
    pack_name,
    parse_json_bytes,
    sha256_bytes,
)

_ZIP_DATE = (1980, 1, 1, 0, 0, 0)   # 固定 zip 时间戳，保证可复现


# ---------------------------------------------------------------- A 侧读取
def read_a_files(server_dir) -> dict:
    """从 server 目录拷 8 个契约文件（存在才拷；l1 缺失即失败）。"""
    srv = Path(server_dir).expanduser().resolve()
    if not srv.is_dir():
        raise PackError("--server 不是目录：%s" % srv)
    files = {}
    for rel, kind in PACK_FILES.items():
        p = srv / rel
        if p.is_file():
            files[rel] = p.read_bytes()
        elif kind == "required":
            raise PackError("server 目录缺少必需文件：%s" % p)
    return files


def _read_friends(server_dir) -> bytes:
    p = Path(server_dir) / "data" / "friends.json"
    if not p.is_file():
        raise PackError("--with-friends 但 server 目录没有 data/friends.json：%s" % p)
    return p.read_bytes()


# ---------------------------------------------------------------- 打包
def build_pack(server_dir, out_zip, source, *, capture=None, snapshot=None,
               with_friends=False, live_collector=None) -> dict:
    """造一个存档包，返回 meta dict。source ∈ local | snapshot | local+b。"""
    if source not in ("local", "snapshot", "local+b"):
        raise PackError("未知来源：%r" % source)

    srv = Path(server_dir).expanduser().resolve()
    files = read_a_files(srv)
    uid = normalize_mod.read_uid(files[L1_PATH])

    changed, norm_warnings = normalize_mod.normalize_files(files, uid)
    origins = {rel: ("normalize" if rel in changed else "copy") for rel in files}

    b_info = {"used": False, "b_uid": None, "applied": [], "endpoints": []}
    if source == "snapshot":
        snap_path = snapshot or (srv / "samples" / "samples.json")
        b = snapshot_mod.load_snapshot(snap_path)
        if merge_mod.has_b_payload(b) or b.get("uid"):
            applied, b_uid = merge_mod.apply_b(files, uid, b, with_friends)
            for rel in applied:
                origins[rel] = "merge"
            b_info.update({"used": True, "b_uid": b_uid, "applied": applied,
                           "endpoints": [{"route": k, "origin": b.get("origin")}
                                         for k in ("mail", "friends", "rank", "event")
                                         if b.get(k) is not None]})
    elif source == "local+b":
        if not capture:
            raise PackError("--from local+b 需要 --capture <pcapng>")
        collector = live_collector  # 注入点（自测用）；默认走真实网络
        if collector is None:
            from . import live
            collector = live.collect_b
        b = collector(capture, srv)
        applied, b_uid = merge_mod.apply_b(files, uid, b, with_friends)
        for rel in applied:
            origins[rel] = "merge"
        b_info.update({"used": True, "b_uid": b_uid, "applied": applied,
                       "endpoints": b.get("endpoints", [])})

    if with_friends and merge_mod.FRIENDS_PATH not in files:
        # friends.json 已在 PACK_FILES 里由 read_a_files 读过（存在就拷），
        # 这里只在「B 没给、A 侧也没有」时补拷，避免重复写同一个成员。
        files[merge_mod.FRIENDS_PATH] = _read_friends(srv)
        origins[merge_mod.FRIENDS_PATH] = "copy"

    l1_obj = parse_json_bytes(files[L1_PATH], L1_PATH)
    baseline = validate_mod.compute_baseline(srv)
    val_errors, val_warnings = validate_mod.validate_l1(l1_obj, baseline, srv)
    if val_errors:
        raise PackError("l1 校验失败，拒绝打包：%s" % "; ".join(val_errors))
    warnings = norm_warnings + val_warnings

    out = Path(out_zip).expanduser().resolve()
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    expected_name = pack_name(uid)
    name_warning = None
    if out.name != expected_name:
        name_warning = ("输出名 %s 不符合契约名 %s（手机端按 save-<uid>-<yyyymmdd>"
                        ".gfsave.zip 识别）" % (out.name, expected_name))
        warnings.append(name_warning)

    now = datetime.now(timezone.utc)
    meta = {
        "format": "gfsave-1",
        "source": source,
        "uid": uid,
        "created_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_local": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pack_name": out.name,
        "friends_included": merge_mod.FRIENDS_PATH in files,
        "normalize": {"changed": changed},
        "merge": b_info,
        "validate": {
            "baseline_key_count": len(baseline),
            "baseline_missing": [k for k in baseline if k not in l1_obj],
            "errors": [],
            "warnings": warnings,
        },
        "files": {},
    }
    for rel in sorted(files):
        data = files[rel]
        meta["files"][rel] = {
            "sha256": sha256_bytes(data),
            "bytes": len(data),
            "count": count_of(parse_json_bytes(data, rel)),
            "origin": origins.get(rel, "copy"),
        }
    meta["file_count"] = len(files)
    meta["total_bytes"] = sum(v["bytes"] for v in meta["files"].values())

    _write_zip(out, files, meta)
    return meta


def _write_zip(out: Path, files: dict, meta: dict) -> None:
    members = [(rel, files[rel]) for rel in sorted(files)]
    members.append((META_NAME,
                    json.dumps(meta, ensure_ascii=False, indent=2,
                               sort_keys=True).encode("utf-8")))
    tmp = out.with_suffix(out.suffix + ".tmp")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in members:
                zi = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o644 << 16
                zf.writestr(zi, data)
        tmp.replace(out)
    finally:
        if tmp.exists():
            tmp.unlink()


# ---------------------------------------------------------------- 读包
def _safe_names(zf: zipfile.ZipFile) -> dict:
    """成员名 → 字节；拒绝契约外路径与路径穿越。"""
    allowed = set(PACK_FILES) | EXTRA_ALLOWED | {META_NAME}
    out = {}
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            raise PackError("zip 内出现可疑路径：%r" % info.filename)
        if name not in allowed:
            raise PackError("zip 内出现契约外路径：%r" % info.filename)
        out[name] = zf.read(info)
    return out


def _read_members(zip_path) -> dict:
    """打开 zip 并读出全部成员（含 meta.json）；坏 zip / CRC 损坏 → PackError。"""
    zpath = Path(zip_path).expanduser().resolve()
    if not zpath.is_file():
        raise PackError("存档包不存在：%s" % zpath)
    try:
        with zipfile.ZipFile(zpath) as zf:
            return _safe_names(zf)
    except zipfile.BadZipFile as exc:
        raise PackError("不是有效的 zip（或 CRC 已损坏）：%s —— %s" % (zpath, exc)) from exc


def read_pack(zip_path) -> tuple:
    """读包 → (meta dict, {path: bytes})。缺 meta 即失败。"""
    members = _read_members(zip_path)
    if META_NAME not in members:
        raise PackError("包里没有 %s" % META_NAME)
    meta = parse_json_bytes(members.pop(META_NAME), META_NAME)
    if not isinstance(meta, dict) or not isinstance(meta.get("files"), dict):
        raise PackError("%s 结构不对（缺 files）" % META_NAME)
    return meta, members


# ---------------------------------------------------------------- 校验
def check_pack(zip_path, server_dir=None) -> tuple:
    """完整校验。返回 (ok, report dict)；不抛 PackError（错误进 report）。"""
    report = {"pack": str(Path(zip_path).resolve()), "checks": [],
              "errors": [], "warnings": [], "meta": None}
    err, warn = report["errors"], report["warnings"]

    def bad(msg):
        err.append(msg)

    try:
        meta, members = read_pack(zip_path)
    except PackError as exc:
        bad(str(exc))
        return False, report
    report["meta"] = meta
    listed = meta.get("files") or {}

    # 1) 必需文件
    if L1_PATH not in members:
        bad("缺必需文件 %s" % L1_PATH)

    # 2) 契约路径：包内文件必须都在 meta.files 里登记
    for name in sorted(members):
        if name not in listed:
            bad("包内文件未在 meta.files 登记：%s" % name)
    for name in sorted(listed):
        if name not in members:
            bad("meta.files 登记的文件缺失：%s" % name)

    # 3) 逐文件 sha256 / 字节数 / 条数
    for name in sorted(set(listed) & set(members)):
        want = listed[name] or {}
        data = members[name]
        got_sha = sha256_bytes(data)
        if got_sha != want.get("sha256"):
            bad("%s sha256 不一致（meta=%s 实际=%s）"
                % (name, want.get("sha256"), got_sha))
        if want.get("bytes") is not None and len(data) != want["bytes"]:
            bad("%s 字节数不一致（meta=%s 实际=%s）"
                % (name, want["bytes"], len(data)))
        try:
            obj = json.loads(data.decode("utf-8"))
            got_count = count_of(obj)
            if want.get("count") is not None and got_count != want["count"]:
                bad("%s 条数不一致（meta=%s 实际=%s）"
                    % (name, want["count"], got_count))
        except (UnicodeDecodeError, ValueError):
            bad("%s 不是合法 JSON" % name)

    # 4) uid 规则：以包内 l1.user_info.id 为准，meta.uid 必须一致
    uid_now = None
    if L1_PATH in members:
        try:
            uid_now = normalize_mod.read_uid(members[L1_PATH])
            if meta.get("uid") != uid_now:
                bad("meta.uid=%s 与 l1.user_info.id=%s 不一致"
                    % (meta.get("uid"), uid_now))
            if meta.get("source") not in ("local", "snapshot", "local+b"):
                bad("meta.source 不合法：%r" % meta.get("source"))
        except PackError as exc:
            bad(str(exc))

    # 5) 可选：给 --server 时跑 83 键基线 + STC 告警
    if server_dir is not None:
        if L1_PATH in members:
            try:
                errors, warnings = validate_mod.validate_pack_l1(
                    members[L1_PATH], Path(server_dir).expanduser().resolve())
                err.extend(errors)
                warn.extend(warnings)
            except PackError as exc:
                bad(str(exc))
    else:
        warn.append("未提供 --server，跳过 83 键基线校验")

    report["uid"] = uid_now
    return not err, report


# ---------------------------------------------------------------- 解包
def unpack_pack(zip_path, to_dir) -> dict:
    """解包到目录（保持包内布局：content/…、data/…、meta.json）。"""
    members = _read_members(zip_path)      # 含 meta.json，且路径已过白名单
    if META_NAME not in members:
        raise PackError("包里没有 %s" % META_NAME)
    meta = parse_json_bytes(members[META_NAME], META_NAME)
    dest = Path(to_dir).expanduser().resolve()
    if dest.exists() and not dest.is_dir():
        raise PackError("--to 已存在且不是目录：%s" % dest)
    dest.mkdir(parents=True, exist_ok=True)
    for name in sorted(members):
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(members[name])
    return {"to": str(dest), "files": sorted(members), "uid": meta.get("uid")}
