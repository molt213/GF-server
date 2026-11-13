"""merge：A 打底；B 只覆盖 mail.json、l1.event_info / event_rank_with_user；
--with-friends 才覆盖 data/friends.json（服务端 Friend/list 原样，行数组）。

uid 红线：B 拉到的 uid 与 A（l1.user_info.id）不一致 → PackError，拒绝静默改写。
"""
from __future__ import annotations

from .contract import (
    FRIENDS_PATH,
    L1_PATH,
    MAIL_PATH,
    PackError,
    canonical_json_bytes,
    parse_json_bytes,
)

# B 数据键 → 包内路径（friends 仅 --with-friends 时生效）
_B_KEYS = {
    "mail": MAIL_PATH,
    "friends": FRIENDS_PATH,
    "rank": "l1:event_rank_with_user",
    "event": "l1:event_info",
}


def unwrap_rows(obj, keys=("rank_list", "list", "rows")):
    """响应 → 行数组。数组原样返回；dict 时按候选键解包；否则 None。"""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in keys:
            val = obj.get(key)
            if isinstance(val, list):
                return val
    return None


def _mail_rows(mail):
    """getMailList 官方响应是纯行数组（客户端按下标迭代取 ["id"]）。"""
    rows = unwrap_rows(mail, ("index_getmaillist", "mail_list", "mail", "list"))
    if rows is None:
        raise PackError("B 邮件响应无法映射为 mail.json 行数组（顶层 %s）"
                        % type(mail).__name__)
    return rows


def _friend_rows(friends):
    """friends.json 形态 = Friend/list 原样（服务端按行数组读取）。"""
    rows = unwrap_rows(friends, ("friend_list", "friends", "list"))
    if rows is None:
        raise PackError("B 好友响应无法映射为 data/friends.json 行数组（顶层 %s）"
                        % type(friends).__name__)
    return rows


def apply_b(files: dict, uid: str, b: dict, with_friends: bool) -> tuple:
    """把 B 数据覆盖进 files（path → bytes）。

    返回 (被覆盖的路径列表, b_uid 或 None)。b 可含键：
    uid / mail / friends / rank / event；None 值的键跳过。
    """
    applied = []
    b_uid = b.get("uid")
    if b_uid is not None and str(b_uid) != str(uid):
        raise PackError(
            "B 拉到的 uid=%s 与 A（l1.user_info.id）=%s 不一致 —— 拒绝静默改写"
            % (b_uid, uid))

    mail = b.get("mail")
    if mail is not None:
        files[MAIL_PATH] = canonical_json_bytes(_mail_rows(mail))
        applied.append(MAIL_PATH)

    event = b.get("event")
    rank = b.get("rank")
    if event is not None or rank is not None:
        l1 = parse_json_bytes(files[L1_PATH], L1_PATH)
        if not isinstance(l1, dict):
            raise PackError("l1.json 顶层不是对象，无法合并 B 活动数据")
        if event is not None:
            # B 的 Index/getEventInfo 响应原样覆盖 l1.event_info（键名同源）。
            l1["event_info"] = event
        if rank is not None:
            rows = unwrap_rows(rank)
            if rows is None:
                raise PackError("B 排行响应没有 rank_list 行数组，"
                                "无法映射 event_rank_with_user")
            l1["event_rank_with_user"] = rows
        files[L1_PATH] = canonical_json_bytes(l1)
        applied.append(L1_PATH)

    friends = b.get("friends")
    if with_friends and friends is not None:
        files[FRIENDS_PATH] = canonical_json_bytes(_friend_rows(friends))
        applied.append(FRIENDS_PATH)

    return applied, (str(b_uid) if b_uid is not None else None)


def has_b_payload(b: dict) -> bool:
    """B 是否带了任何可合并的数据（uid 单独存在不算）。"""
    return any(b.get(key) is not None for key in _B_KEYS)
