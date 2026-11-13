"""normalize：账号 id 以 l1.user_info.id 为准，把其它文件里的账号键位对齐。

l1.json 只做身份归一、不动行主键：
- 目标值：user_info.id / user_info.name
- 重写（存在且值不同才改）：user_friend_info.f_userid、user_friend_info.name、
  commander_with_user_info.user_id、commander_uniform_info[*].user_id、
  guide_info.user_id，以及 SELF_UID_TABLES 白名单表里的行级 user_id
- 类型保持：原值是 JSON number 就写 number，是 string 就写 string
- 不碰：行主键 id、from_user_id、to_user_id、medal_id，以及好友/支援/访客
  相关的表（user_friend_info 内部 medal_with_user/team_info/fairy_info 也不动）

其它文件：
- data/daily_quest_state.json            {<uid>: rec}        → 键对齐到 uid
- content/player/mission_reward_ledger.json {<uid>: {mid:1}} → 键对齐到 uid
- data/battle_state.json                 已有 uid 键才对齐（不凭空加键）
- data/friends.json                      行数组，只对齐 is_self 行的
  uid / f_userid / name，好友行一律不动；没有 is_self 行保持原字节
"""
from __future__ import annotations

from .contract import (
    BATTLE_STATE_PATH,
    DAILY_QUEST_PATH,
    FRIENDS_PATH,
    L1_PATH,
    MISSION_LEDGER_PATH,
    PackError,
    canonical_json_bytes,
    parse_json_bytes,
)

# {<uid>: rec} 形态、需要对齐 uid 键的文件
UID_KEYED_PATHS = (DAILY_QUEST_PATH, MISSION_LEDGER_PATH)

# 行级 user_id 判定为「一定是自己」的顶层表（与手机端 SaveImport 同一份白名单）。
# 判据：表名带 _with_user_info / _with_user，或语义上是玩家自己的进度、预设、
# 收藏、排行记录。明确排除 user_friend_info 及好友/赠送/展示表。
SELF_UID_TABLES = (
    "automission_presets_info",
    "battlepass_with_user",
    "breakout_phase_with_user_info",
    "chip_with_user_info",
    "commander_uniform_info",
    "commander_with_user_info",
    "daily_status_with_user_info",
    "dorm_score_info",
    "equip_preset_info",
    "equip_with_user_info",
    "event_rank_with_user",
    "explore_info",
    "fairy_with_user_info",
    "fetter_bounty_with_user",
    "fetter_story_with_user",
    "fetter_with_user",
    "guide_info",
    "gun_preset_info",
    "gun_with_user_info",
    "kalina_with_user_info",
    "mission_with_user_info",
    "org_bounty_with_user",
    "org_department_info",
    "outhouse_establish_info",
    "sangvis_chip_with_user_info",
    "sangvis_preset_info",
    "sangvis_team_with_user_info",
    "sangvis_with_user_info",
    "skin_with_user_info",
    "squad_data_daily",
    "squad_unlock_with_user_info",
    "squad_with_user_info",
    "surplus_datacell_info",
    "targettrain_collect_user_info",
    "team_in_coin_mission_info",
    "trial_exercise_info",
    "trial_with_user_info",
    "user_info",
    "user_record",
    "vehicle_component_with_user_info",
    "vehicle_with_user_info",
    "wish_gun_with_user_info",
)


_MISSING = object()


def _scalar_note(key, val) -> str:
    text = repr(val)
    if len(text) > 40:
        text = text[:37] + "..."
    return "归一丢弃：键 %r 的值不是对象（%s）" % (str(key), text)


def _same_type(old, text: str):
    """原值是 JSON number 就写 number，是 string 就写 string（bool 不算 number）。"""
    if isinstance(old, bool) or not isinstance(old, (int, float)):
        return text
    if isinstance(old, int):
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text
    try:
        return float(text)
    except ValueError:
        return text


def _set_field(rec: dict, field: str, target: str, warnings: list) -> int:
    """存在且值不同才写；返回改写处数。"""
    if field not in rec:
        return 0
    old = rec[field]
    if str(old) == target:
        return 0
    new = _same_type(old, target)
    if (isinstance(old, (int, float)) and not isinstance(old, bool)
            and not isinstance(new, (int, float))):
        warnings.append("%s：原值 %r 是数值，目标 %r 无法写成数值，写入字符串"
                        % (field, old, target))
    rec[field] = new
    return 1


def _set_user_id(rec, target: str, warnings: list) -> int:
    if not isinstance(rec, dict):
        return 0
    if isinstance(rec.get("user_id"), (dict, list)):
        return 0            # 对象/数组形态是畸形数据，不碰
    return _set_field(rec, "user_id", target, warnings)


def _rewrite_user_id_rows(root, target: str, warnings: list) -> int:
    """重写一个表里的行级 user_id。

    兼容三种形态：单行对象（自身有 user_id）、行数组、{id: 行} 映射
    （值可能是行或行数组）。不递归进嵌套对象，避免误碰好友/子表。
    """
    if isinstance(root, dict):
        if "user_id" in root and not isinstance(root["user_id"], (dict, list)):
            return _set_user_id(root, target, warnings)
        n = 0
        for value in root.values():
            n += _rewrite_container(value, target, warnings)
        return n
    return _rewrite_container(root, target, warnings)


def _rewrite_container(node, target: str, warnings: list) -> int:
    if isinstance(node, dict):
        return _set_user_id(node, target, warnings)
    if isinstance(node, list):
        n = 0
        for item in node:
            if isinstance(item, dict):
                n += _set_user_id(item, target, warnings)
            elif isinstance(item, list):
                n += _rewrite_container(item, target, warnings)
        return n
    return 0


def normalize_identity(l1, uid: str) -> tuple:
    """就地归一 l1 的身份字段，返回 (改写处数, 告警列表)。"""
    if not isinstance(l1, dict):
        raise PackError("l1.json 顶层不是对象")
    ui = l1.get("user_info")
    if not isinstance(ui, dict):
        raise PackError("l1.json 缺 user_info —— 身份归一以它为准")
    declared = ui.get("id")
    if not isinstance(declared, str) or not declared:
        raise PackError("l1.json 的 user_info.id 必须是非空字符串")
    target_id = declared
    if str(uid) != target_id:
        raise PackError("身份归一目标不一致：传入 uid=%r，l1.user_info.id=%r"
                        % (uid, target_id))
    name_val = ui.get("name")
    target_name = None if name_val is None else str(name_val)
    warnings: list = []
    count = 0

    friend = l1.get("user_friend_info")
    if isinstance(friend, dict):
        count += _set_field(friend, "f_userid", target_id, warnings)
        if target_name is not None:
            count += _set_field(friend, "name", target_name, warnings)

    for table in SELF_UID_TABLES:
        if table in l1:
            count += _rewrite_user_id_rows(l1[table], target_id, warnings)
    return count, warnings


def rekey_uid_map(obj, uid: str):
    """{<uid>: rec} → {uid: rec}。

    返回 (新对象, 是否有变化, 告警列表)。目标 uid 键（按 str(key)==uid 认领，
    int 键也算）的 dict 记录打底、其它 uid 键的 dict 值合并进来（目标键后写
    覆盖）；标量值不会静默丢弃：有 dict 值时逐条告警后丢弃，没有任何 dict
    值时保留第一条标量兜底、其余告警丢弃。
    """
    if not isinstance(obj, dict):
        return obj, False, []
    target = str(uid)
    if all(isinstance(k, str) for k in obj) and set(obj) == {target}:
        return obj, False, []  # 已对齐且键型正确：保持原字节
    merged: dict = {}
    target_val = _MISSING
    other_scalars = []                      # [(key, val)] 按遇到顺序
    for key, val in obj.items():
        if str(key) == target:
            target_val = val
        elif isinstance(val, dict):
            merged.update(val)
        else:
            other_scalars.append((key, val))

    warnings: list = []
    value: object
    if merged:
        value = merged
        if target_val is not _MISSING and not isinstance(target_val, dict):
            warnings.append(_scalar_note("目标键", target_val))
        for key, val in other_scalars:
            warnings.append(_scalar_note(key, val))
    elif target_val is not _MISSING:
        value = target_val                  # 目标键标量兜底
        for key, val in other_scalars:
            warnings.append(_scalar_note(key, val))
    elif other_scalars:
        value = other_scalars[0][1]         # 无 dict 值：保留第一条标量
        for key, val in other_scalars[1:]:
            warnings.append(_scalar_note(key, val))
    else:
        value = {}
    return {target: value}, True, warnings


def align_battle_state(obj, uid: str):
    """battle_state 只在已有 uid 键时对齐（键值不一致才改写）。"""
    if not isinstance(obj, dict) or "uid" not in obj:
        return obj, False
    if str(obj["uid"]) == str(uid):
        return obj, False
    obj["uid"] = str(uid)
    return obj, True


def _is_self(value) -> bool:
    """friends.json 的 is_self 真值：JSON true、数字 1、字符串 "1"。"""
    return value is True or value == 1 or value == "1"


def align_friends_rows(rows, uid: str, name=None):
    """friends.json 行数组的身份对齐：只改 is_self 行，好友行绝不碰。

    只改 is_self 行里已存在的 uid / f_userid（→ uid）与 name（→ l1 的
    user_info.name）；字段原值类型保持。行数组之外、或没有 is_self 行时
    原样返回 False，调用方据此保留原字节（sha256 可复现）。

    返回 (rows, 是否改写, 告警列表)。
    """
    if not isinstance(rows, list):
        return rows, False, []
    warnings: list = []
    count = 0
    for row in rows:
        if not isinstance(row, dict) or not _is_self(row.get("is_self")):
            continue
        count += _set_field(row, "uid", str(uid), warnings)
        count += _set_field(row, "f_userid", str(uid), warnings)
        if name is not None:
            count += _set_field(row, "name", name, warnings)
    return rows, bool(count), warnings


def normalize_files(files: dict, uid: str) -> tuple:
    """就地归一 files（path → bytes）。返回 (改写路径列表, 告警列表)。"""
    changed, warnings = [], []
    l1_obj = None
    if L1_PATH in files:
        l1_obj = parse_json_bytes(files[L1_PATH], L1_PATH)
        count, notes = normalize_identity(l1_obj, uid)
        warnings.extend("%s：%s" % (L1_PATH, note) for note in notes)
        if count:
            files[L1_PATH] = canonical_json_bytes(l1_obj)
            changed.append(L1_PATH)
    for rel in UID_KEYED_PATHS:
        if rel not in files:
            continue
        obj = parse_json_bytes(files[rel], rel)
        new, did, notes = rekey_uid_map(obj, uid)
        if not did:
            continue
        if isinstance(new, dict) and not isinstance(new.get(str(uid)), dict):
            warnings.append("%s：uid 键下的值不是对象，归一后原样保留" % rel)
        for note in notes:
            warnings.append("%s：%s" % (rel, note))
        files[rel] = canonical_json_bytes(new)
        changed.append(rel)
    if BATTLE_STATE_PATH in files:
        obj = parse_json_bytes(files[BATTLE_STATE_PATH], BATTLE_STATE_PATH)
        new, did = align_battle_state(obj, uid)
        if did:
            files[BATTLE_STATE_PATH] = canonical_json_bytes(new)
            changed.append(BATTLE_STATE_PATH)
    if FRIENDS_PATH in files:
        target_name = None
        if isinstance(l1_obj, dict):
            ui = l1_obj.get("user_info")
            if isinstance(ui, dict) and ui.get("name") is not None:
                target_name = str(ui["name"])
        obj = parse_json_bytes(files[FRIENDS_PATH], FRIENDS_PATH)
        new, did, notes = align_friends_rows(obj, uid, target_name)
        warnings.extend("%s：%s" % (FRIENDS_PATH, note) for note in notes)
        if did:
            files[FRIENDS_PATH] = canonical_json_bytes(new)
            changed.append(FRIENDS_PATH)
    return changed, warnings


def read_uid(l1_bytes: bytes) -> str:
    """l1.user_info.id（字符串数字）。缺失/非字符串 → 报错，不猜。"""
    l1 = parse_json_bytes(l1_bytes, "content/player/l1.json")
    if not isinstance(l1, dict):
        raise PackError("l1.json 顶层不是对象")
    ui = l1.get("user_info")
    if not isinstance(ui, dict) or not ui.get("id"):
        raise PackError("l1.json 缺 user_info.id —— 账号 id 以它为准")
    uid = ui["id"]
    if not isinstance(uid, str):
        raise PackError("user_info.id 必须是字符串（数值保持字符串），实际 %r" % (uid,))
    return uid
