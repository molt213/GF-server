"""savepack 离线自测。

用法::

    python tools/savepack/selftest.py --quick [--server <dir>] [--keep]

--quick 全程不联网：用真实 server 目录（A 侧）+ 合成快照（B 侧）走
pack → verify → inspect → unpack → 逐文件 sha256 比对，外加 merge/normalize/
validate/uid 红线的离线单测。全过退出 0，任一步失败退出 1。60 秒内跑完。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import savepack  # noqa: E402
from savepack import merge as merge_mod  # noqa: E402
from savepack import normalize as normalize_mod  # noqa: E402
from savepack import packer  # noqa: E402
from savepack import validate as validate_mod  # noqa: E402
from savepack.cli import main as cli_main  # noqa: E402
from savepack.contract import (  # noqa: E402
    FRIENDS_PATH,
    L1_PATH,
    META_NAME,
    PACK_FILES,
    PackError,
    pack_name,
    sha256_bytes,
)

# 自测要拿一份真实的私服 server/ 树当输入（S1/S2/S7 用它验证「真实 l1」路径）。
# 用 --server 或 GF_SERVER_DIR 指过去；没有就只跑不依赖它的步骤。
DEFAULT_SERVER = os.environ.get("GF_SERVER_DIR") or r"D:/claude/gf/gfserver/server"

_STEPS = []


def step(name):
    def deco(fn):
        _STEPS.append((name, fn))
        return fn
    return deco


class Ctx:
    def __init__(self, server: Path, tmp: Path):
        self.server = server
        self.tmp = tmp
        self.uid = None
        self.zip_local = None
        self.meta_local = None


# ------------------------------------------------------------------ 快照造数
def make_snapshot_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "Index_getMailList.json").write_text(json.dumps([
        {"id": "m1", "title": "B-mail-1"}, {"id": "m2", "title": "B-mail-2"},
    ], ensure_ascii=False), encoding="utf-8")
    (d / "Friend_list.json").write_text(json.dumps([
        {"uid": "202572", "name": "friendA"}, {"uid": "202573", "name": "friendB"},
    ], ensure_ascii=False), encoding="utf-8")
    (d / "Index_rank.json").write_text(json.dumps({
        "rank_list": [{"user_id": "1000001", "rank": 1, "score": 100}],
        "count": 1,
    }, ensure_ascii=False), encoding="utf-8")
    (d / "Index_getEventInfo.json").write_text(json.dumps({
        "1850": {"id": "1850", "code": "wishGunDevelop", "condition": "x"},
    }, ensure_ascii=False), encoding="utf-8")


# ------------------------------------------------------------------ 步骤
@step("S1 pack --from local（真实 server 目录）")
def s1(ctx: Ctx):
    l1 = json.loads((ctx.server / L1_PATH).read_text(encoding="utf-8"))
    ctx.uid = str(l1["user_info"]["id"])
    ctx.zip_local = ctx.tmp / pack_name(ctx.uid)
    rc = cli_main(["pack", "--from", "local", "--server", str(ctx.server),
                   "--out", str(ctx.zip_local)])
    assert rc == 0, "pack local 退出码 %s" % rc
    assert ctx.zip_local.is_file(), "包没生成"
    meta, members = packer.read_pack(ctx.zip_local)
    ctx.meta_local = meta
    assert meta["source"] == "local" and meta["uid"] == ctx.uid
    return "uid=%s 文件=%d" % (meta["uid"], meta["file_count"])


@step("S2 python -m savepack verify（子进程，退出码 0）")
def s2(ctx: Ctx):
    import os
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "savepack", "verify", str(ctx.zip_local),
         "--server", str(ctx.server)],
        cwd=str(TOOLS_DIR), capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env, timeout=60)
    assert proc.returncode == 0, "verify 退出码 %s\nstdout:%s\nstderr:%s" % (
        proc.returncode, proc.stdout[-800:], proc.stderr[-800:])
    return "rc=0"


@step("S3 inspect（退出码 0，输出含 uid 与校验结论）")
def s3(ctx: Ctx):
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli_main(["inspect", str(ctx.zip_local), "--server", str(ctx.server)])
    out = buf.getvalue()
    assert rc == 0, "inspect 退出码 %s" % rc
    assert ctx.uid in out, "inspect 输出缺 uid"
    assert "PASS" in out, "inspect 输出缺校验结论"
    for rel in ctx.meta_local["files"]:
        assert rel in out, "inspect 输出缺 %s" % rel
    return "条目 %d" % len(ctx.meta_local["files"])


@step("S4 unpack → 逐文件 sha256 比对（meta + 源文件）")
def s4(ctx: Ctx):
    to = ctx.tmp / "unpack_local"
    res = packer.unpack_pack(ctx.zip_local, to)
    meta = ctx.meta_local
    assert sorted(res["files"]) == sorted(list(meta["files"]) + [META_NAME]), \
        "解包文件集与 meta 不一致：%s" % res["files"]
    assert (to / META_NAME).is_file(), "meta.json 没解出来"
    for rel, info in meta["files"].items():
        data = (to / rel).read_bytes()
        assert sha256_bytes(data) == info["sha256"], "%s sha256 与 meta 不符" % rel
        if info["origin"] == "copy":
            src = (ctx.server / rel).read_bytes()
            assert sha256_bytes(src) == info["sha256"], \
                "%s 应与 server 源文件逐字节一致" % rel
    return "%d 个文件全部一致" % len(meta["files"])


@step("S5 契约路径核对（包内 = server 里实际存在的 8 路径）")
def s5(ctx: Ctx):
    expect = sorted(rel for rel in PACK_FILES
                    if (ctx.server / rel).is_file())
    absent = sorted(rel for rel in PACK_FILES
                    if not (ctx.server / rel).is_file())
    got = sorted(ctx.meta_local["files"])
    assert got == expect, "包内 %s != 期望 %s" % (got, expect)
    assert FRIENDS_PATH in ctx.meta_local["files"], \
        "local 模式应把 server 的 data/friends.json 拷进包"
    return "打包 %d 个数据文件（server 缺 %s）" % (
        len(expect), ", ".join(absent) or "无")


@step("S6 uid 规则与契约文件名")
def s6(ctx: Ctx):
    assert ctx.meta_local["uid"] == ctx.uid
    assert ctx.zip_local.name == pack_name(ctx.uid), \
        "包名 %s 不符契约" % ctx.zip_local.name
    un = ctx.tmp / "unpack_local" / L1_PATH
    l1 = json.loads(un.read_text(encoding="utf-8"))
    assert str(l1["user_info"]["id"]) == ctx.uid, "l1.user_info.id 被改写"
    fi = l1.get("user_friend_info") or {}
    src = json.loads((ctx.server / L1_PATH).read_text(encoding="utf-8"))
    src_fi = src.get("user_friend_info") or {}
    assert str(fi.get("f_userid")) == ctx.uid, \
        "user_friend_info.f_userid 应归一为 uid"
    assert fi.get("name") == l1["user_info"].get("name"), \
        "user_friend_info.name 应归一为 user_info.name"
    if isinstance(src_fi.get("f_userid"), (int, float)):
        assert isinstance(fi.get("f_userid"), (int, float)), \
            "f_userid 原值是数字，归一后不许变字符串"
    # 行级 user_id：白名单表应全部对齐；好友卡内部展示数据不许动
    rows = l1.get("mission_with_user_info") or []
    assert rows and all(str(r.get("user_id")) == ctx.uid
                        for r in rows if isinstance(r, dict)), \
        "mission_with_user_info.user_id 未归一"
    nested = (fi.get("medal_with_user") or [{}])[0]
    src_nested = (src_fi.get("medal_with_user") or [{}])[0]
    assert nested.get("user_id") == src_nested.get("user_id"), \
        "好友卡内部 user_id 不许动"
    return "uid=%s 身份已归一" % ctx.uid


@step("S7 pack --from snapshot --with-friends（B 覆盖面精确）")
def s7(ctx: Ctx):
    snap = ctx.tmp / "snap_dir"
    make_snapshot_dir(snap)
    zout = ctx.tmp / "s7" / pack_name(ctx.uid)
    rc = cli_main(["pack", "--from", "snapshot", "--server", str(ctx.server),
                   "--out", str(zout), "--snapshot", str(snap),
                   "--with-friends"])
    assert rc == 0, "pack snapshot 退出码 %s" % rc
    meta, members = packer.read_pack(zout)
    ok, rep = packer.check_pack(zout, server_dir=str(ctx.server))
    assert ok, "snapshot 包 verify 失败：%s" % rep["errors"]
    assert meta["source"] == "snapshot"

    mail = json.loads(members["content/player/mail.json"].decode("utf-8"))
    assert [m["id"] for m in mail] == ["m1", "m2"], "mail.json 未被 B 覆盖"
    friends = json.loads(members["data/friends.json"].decode("utf-8"))
    assert [f["uid"] for f in friends] == ["202572", "202573"]
    l1 = json.loads(members[L1_PATH].decode("utf-8"))
    assert l1["event_info"] == {"1850": {"id": "1850", "code": "wishGunDevelop",
                                         "condition": "x"}}, "l1.event_info 未被 B 覆盖"
    assert l1["event_rank_with_user"] == [{"user_id": "1000001", "rank": 1,
                                           "score": 100}], "event_rank_with_user 未被 B 覆盖"
    assert str(l1["user_info"]["id"]) == ctx.uid, "merge 不许改 user_info.id"

    # B 没碰的文件必须保持源字节
    for rel, info in meta["files"].items():
        if info["origin"] == "copy":
            src = (ctx.server / rel).read_bytes()
            assert members[rel] == src, "%s 不该被 B 改动" % rel
    return "覆盖=%s" % ",".join(meta["merge"]["applied"])


@step("S7b samples.json 风格快照（只给 rank，其余保持 A）")
def s7b(ctx: Ctx):
    samples = ctx.tmp / "samples_b.json"
    samples.write_text(json.dumps({"responses": {
        "/index.php/1000/Index/rank": {"rank_list": [{"user_id": "x", "rank": 9}],
                                       "count": 1},
    }}, ensure_ascii=False), encoding="utf-8")
    zout = ctx.tmp / "s7b" / pack_name(ctx.uid)
    rc = cli_main(["pack", "--from", "snapshot", "--server", str(ctx.server),
                   "--out", str(zout), "--snapshot", str(samples)])
    assert rc == 0, "pack snapshot(samples) 退出码 %s" % rc
    meta, members = packer.read_pack(zout)
    l1 = json.loads(members[L1_PATH].decode("utf-8"))
    assert l1["event_rank_with_user"] == [{"user_id": "x", "rank": 9}]
    src_l1 = json.loads((ctx.server / L1_PATH).read_text(encoding="utf-8"))
    assert l1["event_info"] == src_l1["event_info"], "B 没给 event 就不该动 event_info"
    assert members["content/player/mail.json"] == (ctx.server / "content/player/mail.json").read_bytes(), \
        "B 没给 mail 就不该动 mail.json"
    # friends.json 现在在契约内：没有 is_self 行时必须保持 A 侧原字节；
    # 有 is_self 行时只允许那一行按归一规则变，好友行一个字节都不能动。
    src_friends = json.loads((ctx.server / FRIENDS_PATH).read_text(encoding="utf-8"))
    out_friends = json.loads(members[FRIENDS_PATH].decode("utf-8"))

    def _non_self(rows):
        return [json.dumps(r, sort_keys=True, ensure_ascii=False) for r in rows
                if not (isinstance(r, dict) and normalize_mod._is_self(r.get("is_self")))]

    assert _non_self(out_friends) == _non_self(src_friends), \
        "friends.json 的非 is_self 行（好友行）不得被改写"
    if not any(isinstance(r, dict) and normalize_mod._is_self(r.get("is_self"))
               for r in src_friends):
        assert members[FRIENDS_PATH] == (ctx.server / FRIENDS_PATH).read_bytes(), \
            "没有 is_self 行时 friends.json 应保持 A 侧原字节"
    return "rank 覆盖，其余保 A"


@step("S8 uid 红线：B 的 uid 与 A 不同必须报错")
def s8(ctx: Ctx):
    l1_bytes = (ctx.server / L1_PATH).read_bytes()
    files = {L1_PATH: l1_bytes}
    try:
        merge_mod.apply_b(files, ctx.uid, {"uid": "1" * len(ctx.uid),
                                           "mail": [{"id": "z"}]},
                          with_friends=False)
    except PackError as exc:
        assert "拒绝静默改写" in str(exc), "报错信息不对：%s" % exc
        return "PackError: %s…" % str(exc)[:48]
    raise AssertionError("uid 不一致居然没报错")


@step("S9 篡改检测：改包内 l1 一个字节 → verify FAIL")
def s9(ctx: Ctx):
    bad_zip = ctx.tmp / "tampered.gfsave.zip"
    with zipfile.ZipFile(ctx.zip_local) as zin, \
            zipfile.ZipFile(bad_zip, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info)
            if info.filename == L1_PATH:
                data = b"{}"
            zout.writestr(info, data)
    ok, rep = packer.check_pack(bad_zip, server_dir=str(ctx.server))
    assert not ok, "篡改包竟然 PASS"
    assert any("sha256" in e or "不是合法 JSON" in e or "user_info" in e
               for e in rep["errors"]), "错误原因不对：%s" % rep["errors"]
    return "errors=%d" % len(rep["errors"])


@step("S10 normalize 单测（uid 键位对齐 + l1 身份归一 + 标量不静默丢）")
def s10(ctx: Ctx):
    new, did, notes = normalize_mod.rekey_uid_map({"111": {"a": 1}}, "9900001")
    assert did and new == {"9900001": {"a": 1}} and not notes
    new, did, notes = normalize_mod.rekey_uid_map({"9900001": {"a": 1}}, "9900001")
    assert not did and new == {"9900001": {"a": 1}}
    new, did, notes = normalize_mod.rekey_uid_map({111: {"a": 1}}, "111")
    assert did and new == {"111": {"a": 1}}, "int 键也要对齐：%r" % (new,)
    new, did, notes = normalize_mod.rekey_uid_map(
        {"111": {"a": 1}, "222": {"b": 2}}, "9900001")
    assert did and new == {"9900001": {"a": 1, "b": 2}}
    # 标量不许静默丢：dict 值在场时丢弃必须有告警
    new, did, notes = normalize_mod.rekey_uid_map(
        {"111": {"a": 1}, "222": "keep-me"}, "9900001")
    assert did and new == {"9900001": {"a": 1}}, repr(new)
    assert any("222" in w and "丢弃" in w for w in notes), \
        "标量丢弃要有告警：%r" % (notes,)
    # 没有任何 dict 值时：第一条标量兜底保留，其余告警丢弃
    new, did, notes = normalize_mod.rekey_uid_map(
        {"222": "keep-me", "333": "drop-me"}, "9900001")
    assert did and new == {"9900001": "keep-me"}, repr(new)
    assert any("333" in w for w in notes), repr(notes)
    new, did = normalize_mod.align_battle_state(
        {"uid": "111", "turn": 2}, "9900001")
    assert did and new["uid"] == "9900001" and new["turn"] == 2
    new, did = normalize_mod.align_battle_state({"mission_id": 1}, "9900001")
    assert not did and "uid" not in new, "没有 uid 键就不该凭空加"

    # l1 身份归一：只改白名单字段，number/string 类型保持，好友卡内部不动
    l1 = {
        "user_info": {"id": "9900001", "name": "指挥官M2"},
        "user_friend_info": {"f_userid": 1000001, "name": "测试指挥官",
                             "medal_with_user": [{"user_id": "1000001"}]},
        "commander_with_user_info": {"user_id": "1000001"},
        "commander_uniform_info": [{"user_id": "1000001"}],
        "guide_info": {"user_id": 1000001},
        "mission_with_user_info": [{"id": "1", "user_id": "1000001"}],
        "squad_data_daily": [{"user_id": 1000001}],
    }
    count, notes = normalize_mod.normalize_identity(l1, "9900001")
    assert count == 7, count
    assert not notes, notes
    assert l1["user_friend_info"]["f_userid"] == 9900001
    assert isinstance(l1["user_friend_info"]["f_userid"], int)
    assert l1["user_friend_info"]["name"] == "指挥官M2"
    assert l1["user_friend_info"]["medal_with_user"][0]["user_id"] == "1000001"
    assert l1["commander_with_user_info"]["user_id"] == "9900001"
    assert isinstance(l1["commander_uniform_info"][0]["user_id"], str)
    assert l1["guide_info"]["user_id"] == 9900001
    assert isinstance(l1["guide_info"]["user_id"], int)
    assert l1["mission_with_user_info"][0]["user_id"] == "9900001"
    assert l1["mission_with_user_info"][0]["id"] == "1"
    assert l1["squad_data_daily"][0]["user_id"] == 9900001
    assert isinstance(l1["squad_data_daily"][0]["user_id"], int)
    return "rekey/align/身份归一/告警 全过"


@step("S10b friends.json 身份对齐：只改 is_self 行，好友行原样")
def s10b(ctx: Ctx):
    l1_bytes = json.dumps({
        "user_info": {"id": "9900001", "name": "指挥官M2"},
    }, ensure_ascii=False).encode("utf-8")
    rows = [
        {"uid": 1000001, "f_userid": 1000001, "name": "测试指挥官", "is_self": 1},
        {"uid": 202572, "f_userid": 202572, "name": "好友A", "is_self": 0},
        {"uid": 202573, "f_userid": 202573, "name": "好友B", "is_self": False},
    ]
    files = {L1_PATH: l1_bytes,
             FRIENDS_PATH: json.dumps(rows, ensure_ascii=False).encode("utf-8")}
    changed, notes = normalize_mod.normalize_files(files, "9900001")
    assert FRIENDS_PATH in changed, "friends.json 的 is_self 行未对齐：%s" % changed
    assert not notes, notes
    out = json.loads(files[FRIENDS_PATH].decode("utf-8"))
    assert str(out[0]["uid"]) == "9900001", out[0]
    assert out[0]["f_userid"] == 9900001, "原值是数字，对齐后应保持数字：%r" % (out[0],)
    assert out[0]["name"] == "指挥官M2", out[0]
    assert out[1] == rows[1] and out[2] == rows[2], \
        "好友行的 uid/f_userid/name 一律不许动：%r" % (out[1:],)

    # 没有 is_self 行：原字节返回，不做 canonical 重写（sha256 可复现）
    raw = json.dumps([{"uid": 202572, "f_userid": 202572, "name": "好友A",
                       "is_self": 0}], ensure_ascii=False).encode("utf-8")
    files2 = {L1_PATH: l1_bytes, FRIENDS_PATH: raw}
    changed2, _ = normalize_mod.normalize_files(files2, "9900001")
    assert FRIENDS_PATH not in changed2, changed2
    assert files2[FRIENDS_PATH] == raw, "没有 is_self 行时不许重写 friends.json"
    return "is_self 行对齐，好友行原样"


@step("S11 validate：83 键基线现算 + 字符串数值红线 + STC 只告警")
def s11(ctx: Ctx):
    baseline = validate_mod.compute_baseline(ctx.server)
    assert len(baseline) == 83, "基线应为 83 键，实际 %d" % len(baseline)
    errors, warnings = validate_mod.validate_pack_l1(
        (ctx.server / L1_PATH).read_bytes(), ctx.server)
    assert not errors, "真实 l1 不该有基线错误：%s" % errors
    # 数值漂移：id 改成 int → 必须报错
    bad = json.loads(json.dumps(baseline))
    bad["user_info"]["id"] = 1000002
    errors, _ = validate_mod.validate_l1(bad, baseline, ctx.server)
    assert any("user_info.id" in e for e in errors), "int id 应报错：%s" % errors
    # 缺键：去掉一个非 user_info 基线键 → 报错
    drop = [k for k in baseline if k != "user_info"][-1]
    less = {k: v for k, v in baseline.items() if k != drop}
    errors, _ = validate_mod.validate_l1(less, baseline, ctx.server)
    assert any("缺官方基线键" in e for e in errors)
    return "基线 83 键，真实 l1 errors=0 warnings=%d" % len(warnings)


# ------------------------------------------------------------------ pcapng 造数
def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % 4)


def _block(btype: int, body: bytes, order: str) -> bytes:
    total = 12 + len(body)
    return (btype.to_bytes(4, order) + total.to_bytes(4, order)
            + body + total.to_bytes(4, order))


def _mk_pcapng(frames, linktype: int = 1, order: str = "little",
               extra: bytes = b"") -> bytes:
    """在内存里造一个 pcapng（一个 section、一个 interface、若干 EPB）。"""
    bom = (b"\x4d\x3c\x2b\x1a" if order == "little"
           else b"\x1a\x2b\x3c\x4d")
    out = _block(0x0A0D0D0A,
                 bom + (1).to_bytes(2, order) + (0).to_bytes(2, order)
                 + (-1).to_bytes(8, order, signed=True), order)
    out += _block(1, linktype.to_bytes(2, order) + b"\x00\x00"
                  + (0).to_bytes(4, order), order)
    out += extra
    for frame in frames:
        out += _block(6,
                      (0).to_bytes(4, order) + (0).to_bytes(4, order)
                      + (0).to_bytes(4, order) + len(frame).to_bytes(4, order)
                      + len(frame).to_bytes(4, order) + _pad4(frame), order)
    return out


def _ip4addr(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def _ipv4(payload: bytes, src: str, dst: str) -> bytes:
    total = 20 + len(payload)
    return (b"\x45\x00" + total.to_bytes(2, "big") + b"\x00\x00\x00\x00"
            + bytes([64, 6]) + b"\x00\x00"
            + _ip4addr(src) + _ip4addr(dst) + payload)


def _tcp(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + seq.to_bytes(4, "big") + (0).to_bytes(4, "big")
            + b"\x50\x18" + (65535).to_bytes(2, "big")
            + b"\x00\x00" + b"\x00\x00" + payload)


def _frame(sport: int, dport: int, seq: int, payload: bytes,
           vlan=None, raw_ip: bool = False, reverse: bool = False) -> bytes:
    """造一个 TCP 帧。reverse=True 表示服务端→客户端方向。"""
    if reverse:
        src, dst = "60.205.104.31", "10.0.0.2"
    else:
        src, dst = "10.0.0.2", "60.205.104.31"
    ip = _ipv4(_tcp(sport, dport, seq, payload), src, dst)
    if raw_ip:
        return ip
    head = (bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb"))
    if vlan:
        head += ((0x8100).to_bytes(2, "big") + vlan.to_bytes(2, "big")
                 + (0x0800).to_bytes(2, "big"))
    else:
        head += b"\x08\x00"
    return head + ip


@step("S12 抓包解析：跨段/VLAN/裸 IP/重复包/响应解 uid")
def s12(ctx: Ctx):
    from savepack import envelope, live, pcapng

    form = b"openid=abc&sid=1&ticket=xyz"
    req = (b"POST /index.php/1000/Index/getUidPC HTTP/1.1\r\n"
           b"Host: gw\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form)
    cred = envelope.encode_bytes(
        json.dumps({"uid": "424242", "sign": "selftest-sign"}).encode(),
        envelope.QUEUE_KEY)
    body = b"#" + cred.encode()
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)

    split = 60
    frames = [
        _frame(51000, 80, 1000, req[:split]),           # 请求前半段
        _frame(51000, 80, 1000 + split, req[split:]),   # 请求后半段（跨段）
        _frame(51000, 80, 1000, req[:split]),           # pktmon 多组件重复包
        _frame(80, 51000, 5000, resp, vlan=100, reverse=True),  # 响应 + VLAN
    ]
    cap = ctx.tmp / "s12_cap.pcapng"
    cap.write_bytes(_mk_pcapng(frames, linktype=1))

    reader = pcapng.Reader(cap)
    count = sum(1 for _ in reader.packets())
    assert count == 4, count
    assert reader.byte_order == "little", reader.byte_order
    assert reader.interfaces[0].linktype == 1

    got, summary = live.first_getuidpc_form(cap)
    assert got == form, "跨段表单没拼对：%r" % got[:40]
    assert set(summary) == {"openid", "sid", "ticket"}, summary

    session, how = live.find_uid_response(cap)
    assert session and session["uid"] == "424242", session
    assert session["sign"] == "selftest-sign", session
    assert how, "没给出凭据来源"

    scan = live.scan_capture(cap)
    assert scan["getuidpc_seen"] == 1, scan["getuidpc_seen"]
    assert len(scan["pairs"]) == 1, scan["pairs"]

    # 裸 IP 帧（pktmon 的 TCPIP 组件层）+ 大端 pcapng
    raw = ctx.tmp / "s12_raw.pcapng"
    raw.write_bytes(_mk_pcapng([_frame(51001, 80, 2000, req, raw_ip=True)],
                               linktype=101, order="big"))
    r2 = pcapng.Reader(raw)
    assert sum(1 for _ in r2.packets()) == 1
    assert r2.byte_order == "big", r2.byte_order
    assert live.first_getuidpc_form(raw)[0] == form

    # 未知块类型要被跳过，后面的包还得能读到
    unknown = _block(0x00000BAD, b"\x00" * 8, "little")
    mixed = ctx.tmp / "s12_mixed.pcapng"
    mixed.write_bytes(_mk_pcapng([_frame(51002, 80, 3000, req)],
                                 extra=unknown))
    assert live.first_getuidpc_form(mixed)[0] == form

    # Index/index 兜底：按路由配对 + 用会话 sign 解
    big = {"k%02d" % i: i for i in range(83)}
    idx_body = b"#" + envelope.encode_bytes(
        json.dumps(big).encode(), "selftest-sign").encode()
    idx_resp = (b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(idx_body)).encode() + b"\r\n\r\n" + idx_body)
    idx_req = (b"POST /index.php/1000/Index/index HTTP/1.1\r\n"
               b"Content-Length: 0\r\n\r\n")
    idx_cap = ctx.tmp / "s12_index.pcapng"
    idx_cap.write_bytes(_mk_pcapng([
        _frame(51003, 80, 4000, idx_req),
        _frame(80, 51003, 6000, idx_resp, reverse=True),
    ]))
    idx_scan = live.scan_capture(idx_cap)
    got_index = live.find_index_response(idx_cap, "selftest-sign", idx_scan)
    assert got_index is not None, "Index/index 响应没能从抓包解出来"
    assert len(got_index) == 83, len(got_index)

    return ("跨段 %dB 拼合、VLAN/裸 IP/大端/未知块全过，响应解出 uid=%s，"
            "Index/index 兜底 %d 键"
            % (len(form), session["uid"], len(got_index)))


@step("S13 空基线拒绝：Index/index={} 不得静默关闭 83 键校验")
def s13(ctx: Ctx):
    fake = ctx.tmp / "fake_srv_empty"
    (fake / "content" / "player").mkdir(parents=True, exist_ok=True)
    (fake / "samples").mkdir(parents=True, exist_ok=True)
    (fake / "content" / "player" / "l1.json").write_text(
        json.dumps({"user_info": {"id": "9900001"}}), encoding="utf-8")
    (fake / "samples" / "samples.json").write_text(
        json.dumps({"responses": {"/index.php/1000/Index/index": {}}}),
        encoding="utf-8")
    zout = ctx.tmp / "s13" / pack_name("9900001")
    rc = cli_main(["pack", "--from", "local", "--server", str(fake),
                   "--out", str(zout)])
    assert rc != 0, "空基线 + 仅 user_info.id 的 l1 打包竟然 rc=0"
    assert not zout.exists(), "拒绝打包时不应产出 zip"
    return "空基线 pack rc=%s（拒绝）" % rc


@step("S14 好友列表：Friend/list 明文/信封都能解 + 转私服行")
def s14(ctx: Ctx):
    from savepack import envelope, live, official

    rows = [
        {"f_userid": 202572, "f_zoneid": "1", "name": "白金", "lv": 148,
         "headpic_id": 42, "frame_id": 3, "max_dorm": 10, "dorm_id": 2,
         "gender": 1, "homepage_time": 1794000000, "is_return_user": 0,
         "gun_collect": 300, "furniture_collect": 500,
         "is_vehicle_visit": 0, "end_time": 0},
        {"f_userid": 650677, "name": "SGWL", "lv": 140, "headpic_id": 7,
         "homepage_time": 1793000000, "max_dorm": 14},
    ]
    payload = {"list": rows}

    def _req(route):
        return (b"POST /index.php/1000/" + route.encode() + b" HTTP/1.1\r\n"
                b"Content-Length: 0\r\n\r\n")

    def _resp(body):
        return (b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)

    # 1) 明文响应（官方 Friend/* 的实际形态）
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    plain = ctx.tmp / "s14_plain.pcapng"
    plain.write_bytes(_mk_pcapng([
        _frame(51100, 80, 7000, _req("Friend/list")),
        _frame(80, 51100, 8000, _resp(body), reverse=True),
    ]))
    obj, how = live.find_friend_list_response(live.scan_capture(plain))
    assert obj is not None, "明文 Friend/list 没取到"
    assert how and "Friend/list" in how, how
    assert len(obj["list"]) == 2, obj

    got = official.friends_to_private(obj)
    assert len(got) == 2, got
    assert got[0]["uid"] == 202572 and got[0]["f_userid"] == 202572
    assert got[0]["name"] == "白金" and got[0]["lv"] == 148
    assert got[0]["zone_id"] == "1", got[0]["zone_id"]
    assert got[0]["last_login"] == 1794000000
    assert got[0]["detail_known"] is False
    assert got[1]["max_dorm"] == 14, got[1]["max_dorm"]

    # 2) 信封响应（万一官方以后包成 #base64，用会话 sign 也要能解）
    sign = "selftest-friend-sign"
    enc = envelope.encode_bytes(
        json.dumps(payload, ensure_ascii=False).encode("utf-8"), sign)
    enc_cap = ctx.tmp / "s14_enc.pcapng"
    enc_cap.write_bytes(_mk_pcapng([
        _frame(51101, 80, 9000, _req("Friend/list")),
        _frame(80, 51101, 9500, _resp(b"#" + enc.encode()), reverse=True),
    ]))
    obj2, _how2 = live.find_friend_list_response(
        live.scan_capture(enc_cap), sign)
    assert obj2 is not None, "信封 Friend/list 没解开"
    assert len(obj2["list"]) == 2, obj2

    # 3) 抓包里没有这条路由 → 安静返回 (None, None)，不抛
    empty = ctx.tmp / "s14_none.pcapng"
    empty.write_bytes(_mk_pcapng([
        _frame(51102, 80, 9600, _req("Index/version")),
    ]))
    obj3, how3 = live.find_friend_list_response(live.scan_capture(empty))
    assert obj3 is None and how3 is None, (obj3, how3)

    return ("明文/信封两路都解出 %d 行，映射 uid=%s、max_dorm=%d"
            % (len(got), got[0]["uid"], got[1]["max_dorm"]))


@step("S15 官方补充键：同名同构才覆盖，其余不动")
def s15(ctx: Ctx):
    from savepack import official

    l1 = official.load_template()
    assert len(l1["furniture_with_user_info"]) == 3205

    fake_furn = [{"dorm": "1", "furniture_id": "9001", "id": "1",
                  "x": 3, "y": 4}]
    extra = {
        "Friend/dormInfo": {
            "furniture_with_user_info": fake_furn,
            "info": {"user_id": "1"},              # 非白名单，不能进 l1
        },
        "Battlepass/index": {
            "battlepass_with_user": [{"battlepass_id": "1", "user_id": "1"}],
            "battlepass_pt_item": [{"id": "1", "pt": "10"}],
        },
        "Daily/index": {
            "daily_status_with_user_info": {"1": {"status": 3}},
        },
        "Chess/index": {
            "chess_info": {"chess_score": 1},      # 结构和 l1 不同，不能硬塞
            "team_list": [],
        },
    }
    applied = official.merge_extra(l1, extra)
    assert set(applied) == {"furniture_with_user_info", "battlepass_with_user",
                            "battlepass_pt_item", "daily_status_with_user_info"}, applied
    assert l1["furniture_with_user_info"] == fake_furn
    assert len(l1["battlepass_with_user"]) == 1
    for bad in ("info", "chess_info", "team_list"):
        assert bad not in l1, "%s 不该被塞进 l1" % bad

    # 一条都没拉到 → 模板原样保留
    l2 = official.load_template()
    assert official.merge_extra(l2, {}) == []
    assert len(l2["furniture_with_user_info"]) == 3205

    # 官方回空表 → 不覆盖（否则宿舍会被清空）
    l3 = official.load_template()
    assert official.merge_extra(
        l3, {"Friend/dormInfo": {"furniture_with_user_info": []}}) == []
    assert len(l3["furniture_with_user_info"]) == 3205

    # to_private 必须把黑卡赠送标记清零，否则导入后新号拿不到首登黑卡
    l4 = official.to_private({"user_info": {"id": "1"}},
                             official.load_template())
    assert l4["blackcard_granted"] == 0, l4["blackcard_granted"]

    return ("覆盖 %d 键；空响应/空表保留模板；非白名单字段不入 l1"
            % len(applied))


@step("S16 本地推算 + 结构转换（建造/兵棋/融合演习/宿舍）")
def s16(ctx: Ctx):
    from savepack import official

    l1 = official.load_template()
    l1["develop_act_info"] = [
        {"build_slot": "1", "gun_id": "347"},
        {"build_slot": "3", "gun_id": "92"},
        {"build_slot": "2", "gun_id": "0"},        # 空槽不记
    ]
    l1["develop_equip_act_info"] = {"1": {"equip_id": "77"},
                                    "2": {"equip_id": "0"}}
    l1["develop_fairy_act_info"] = []
    l1["furniture_with_user_info"] = [
        {"id": "1"}, {"id": "14224052"}, {"id": "99"}]
    l1["squad_skill_act_info"] = [{"slot": "1", "id": "5555"}]
    got = official.derive_local(l1)
    assert set(got) == {"_build_pending", "_equip_build_pending",
                        "_fairy_build_pending", "furniture_id_seq",
                        "squad_skill_slot"}, got
    assert l1["_build_pending"] == {"1": "347", "3": "92"}, l1["_build_pending"]
    assert l1["_equip_build_pending"] == {"1": "77"}, l1["_equip_build_pending"]
    assert l1["_fairy_build_pending"] == {}
    assert l1["furniture_id_seq"] == 14224052, l1["furniture_id_seq"]
    assert l1["squad_skill_slot"] == {"1": {"slot": "1", "id": "5555"}}

    resp = {
        "Chess/index": {
            "chess_info": {"ticket_daily_num": 7,
                           "ticket_daily_refresh_time": 1794000000,
                           "acquired_bonus": "1,18,19,1"},
            "team_list": [{"team_id": 0, "gun_id": 1},
                          {"team_id": 0, "gun_id": 2},
                          {"team_id": 1, "gun_id": 3}],
        },
        "Sangvis/duplicateIndex": {"1": {"win_counter": 3},
                                   "2": {"win_counter": 0}},
        "Friend/dormInfo": {"info": {"dorm_id": "7"}},
        "Dorm/spare_name_list": [{"dorm_spare_id": 101, "dorm_name": "复核房A"}],
    }
    out = official.to_local_from_responses(resp)
    assert out["chess_ticket_daily"] == {"num": "7", "time": "1794000000"}, out
    assert out["chess_gasha_acquired"] == [1, 18, 19], out["chess_gasha_acquired"]
    assert len(out["chess_team"]["0"]) == 2 and len(out["chess_team"]["1"]) == 1
    assert out["sangvis_duplicate_win"] == {"1": 3, "2": 0}
    assert out["dorm_build_coin_current_room"] == "7"
    assert out["dorm_spare_info"] == {
        "101": {"dorm_spare_id": "101", "dorm_name": "复核房A"}}

    assert official.to_local_from_responses({}) == {}
    return "推算 5 键 + 转换 %d 键，空响应不产物" % len(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="savepack.selftest")
    ap.add_argument("--quick", action="store_true", help="离线快速自测（当前唯一模式）")
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--keep", action="store_true", help="保留临时目录（调试用）")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    server = Path(args.server).expanduser().resolve()
    if not server.is_dir():
        print("[selftest] --server 不是目录：%s" % server)
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="savepack_selftest_"))
    ctx = Ctx(server, tmp)
    print("savepack selftest --quick   server=%s" % server)
    print("tmp=%s" % tmp)
    t0 = time.time()
    failed = False
    try:
        for name, fn in _STEPS:
            t = time.time()
            try:
                note = fn(ctx)
                print("  [PASS] %-52s %5.2fs  %s" % (name, time.time() - t, note or ""))
            except Exception as exc:  # noqa: BLE001
                failed = True
                print("  [FAIL] %-52s %5.2fs  %s" % (name, time.time() - t, exc))
                break
    finally:
        if failed and args.keep:
            print("临时目录保留：%s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    dt = time.time() - t0
    print("SELFTEST %s（%.2fs）" % ("PASS" if not failed else "FAIL", dt))
    if dt > 60:
        print("[selftest] 超出 60 秒预算，视为失败")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
