"""snapshot：B 的离线快照 —— 读一个目录，或 samples.json 风格的文件。

目录布局（路由转储，文件名 = 路由下划线写法）::

    Index_getMailList.json / mail.json     → Index/getMailList
    Friend_list.json                       → Friend/list
    Index_rank.json                        → Index/rank
    Index_getEventInfo.json                → Index/getEventInfo

samples.json 风格（server/samples/samples.json 即此形态）::

    {"responses": {"/index.php/1000/Index/getMailList": <解码后的响应>, ...}}

快照里没有账号 uid 时 b_uid 为 None —— B/A 的 uid 一致性校验只对 live 直拉生效。
"""
from __future__ import annotations

import json
from pathlib import Path

from .contract import PackError

# B 数据键 → 匹配路由用的后缀（全小写）
_ROUTES = {
    "mail": ("getmaillist",),
    "friends": ("friend/list",),
    "rank": ("/index/rank",),
    "event": ("geteventinfo",),
}
_ROUTE_STEMS = {
    "mail": ("index_getmaillist", "getmaillist", "mail"),
    "friends": ("friend_list", "friendlist"),
    "rank": ("index_rank", "rank"),
    "event": ("index_geteventinfo", "geteventinfo"),
}


def _suffix_match(route_key: str, text: str) -> bool:
    return any(text.endswith(suf) for suf in _ROUTES[route_key])


def load_snapshot(path) -> dict:
    """读快照 → {"uid": None|str, "mail":…, "friends":…, "rank":…, "event":…, "origin": str}。

    缺的键为 None（merge 时跳过）。
    """
    p = Path(path).expanduser().resolve()
    if p.is_dir():
        return _from_dir(p)
    if p.is_file():
        data = _from_samples_file(p)
        data["origin"] = str(p)
        return data
    raise PackError("B 快照不存在（目录或 samples.json 风格文件）：%s" % p)


def _blank() -> dict:
    return {"uid": None, "mail": None, "friends": None, "rank": None,
            "event": None, "origin": None}


def _from_dir(d: Path) -> dict:
    out = _blank()
    out["origin"] = str(d)
    samples = d / "samples.json"
    if samples.is_file():
        out.update(_from_samples_file(samples))
    for f in sorted(d.glob("*.json")):
        stem = f.stem.lower().replace("-", "_")
        for key, names in _ROUTE_STEMS.items():
            if stem in names and out.get(key) is None:
                out[key] = _load_json(f)
    return out


def _from_samples_file(p: Path) -> dict:
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PackError("samples 文件读取失败 %s：%s" % (p, exc)) from exc
    if not isinstance(obj, dict):
        raise PackError("samples 文件顶层不是对象：%s" % p)
    responses = obj.get("responses") if isinstance(obj.get("responses"), dict) else obj
    out = _blank()
    for route_key, obj_val in _iter_responses(responses):
        for key in _ROUTES:
            if out.get(key) is None and _suffix_match(key, route_key.lower()):
                out[key] = obj_val
                break
    return out


def _iter_responses(responses: dict):
    for route, val in responses.items():
        if isinstance(route, str) and isinstance(val, (dict, list)):
            yield route, val


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PackError("快照响应文件读取失败 %s：%s" % (p, exc)) from exc
