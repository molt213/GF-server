"""存档包契约：路径表、meta.json 字段、确定性序列化与计数。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

META_NAME = "meta.json"
L1_PATH = "content/player/l1.json"
MAIL_PATH = "content/player/mail.json"
MISSION_LEDGER_PATH = "content/player/mission_reward_ledger.json"
BATTLE_STATE_PATH = "data/battle_state.json"
CAREER_LEDGER_PATH = "data/career_claim_ledger.json"
DAILY_QUEST_PATH = "data/daily_quest_state.json"
FRIEND_STATE_PATH = "data/friend_state.json"
FRIENDS_PATH = "data/friends.json"

# 唯一契约：手机端只认这 8 条数据路径（required 表示缺失即打包失败）。
PACK_FILES = {
    L1_PATH: "required",
    MAIL_PATH: "optional",
    MISSION_LEDGER_PATH: "optional",
    BATTLE_STATE_PATH: "optional",
    CAREER_LEDGER_PATH: "optional",
    DAILY_QUEST_PATH: "optional",
    FRIEND_STATE_PATH: "optional",
    FRIENDS_PATH: "optional",
}
REQUIRED_PATHS = [p for p, kind in PACK_FILES.items() if kind == "required"]

# data/friends.json 已并入 PACK_FILES（optional，服务端 Friend/list 原样）；
# EXTRA_ALLOWED 保留常量兼容旧 import，读包白名单与 PACK_FILES 取并集。
EXTRA_ALLOWED = {FRIENDS_PATH}

SOURCES = ("local", "snapshot", "local+b")


class PackError(Exception):
    """savepack 的可预期错误（命令行退出码 1）。"""


def canonical_json_bytes(obj) -> bytes:
    """确定性序列化：紧凑分隔符 + 排序键 + UTF-8、无换行。

    被归一/合并改写过的文件用这个格式重写，保证 meta 里的 sha256 可复算；
    未被改动的文件保持原字节（本地模式整包与源文件逐字节一致）。
    """
    return json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")


def parse_json_bytes(data: bytes, what: str):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackError("%s 不是合法 JSON：%s" % (what, exc)) from exc


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def count_of(obj):
    """meta 里的「条数」：list/dict 取长度，其余类型无条数（None）。"""
    if isinstance(obj, (list, dict)):
        return len(obj)
    return None


def pack_name(uid: str, date=None) -> str:
    """契约文件名 save-<uid>-<yyyymmdd>.gfsave.zip。"""
    import datetime as _dt
    d = date or _dt.date.today()
    return "save-%s-%s.gfsave.zip" % (uid, d.strftime("%Y%m%d"))


def resolve_dir(path, what: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise PackError("%s 不是目录：%s" % (what, p))
    return p


def resolve_file(path, what: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise PackError("%s 不存在：%s" % (what, p))
    return p
