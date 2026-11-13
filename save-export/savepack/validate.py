"""validate：l1 可解析、含 user_info 与官方 83 键基线（现算自 samples.json）、
数值保持字符串、缺失 STC id 只告警。

基线来源：server/samples/samples.json 的 responses["/index.php/1000/Index/index"]
（实测 83 键）。基线每次现算，不缓存到包外。
"""
from __future__ import annotations

import json
from pathlib import Path

from .contract import L1_PATH, PackError

SAMPLES_RELPATH = "samples/samples.json"
INDEX_ROUTE = "/index.php/1000/Index/index"
ITEM_IDS_RELPATH = "data/stc/item_ids.json"

# 报告里 STC 告警最多逐条列出这么多，超出只报总数
_STC_WARN_LIMIT = 20


def compute_baseline(server_dir) -> dict:
    """从 <server>/samples/samples.json 现算 Index/index 基线（含键集与样本值）。"""
    p = Path(server_dir) / SAMPLES_RELPATH
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PackError("83 键基线来源读取失败 %s：%s" % (p, exc)) from exc
    responses = obj.get("responses") if isinstance(obj, dict) else None
    if not isinstance(responses, dict) or INDEX_ROUTE not in responses:
        raise PackError("samples.json 里没有 %s 响应：%s" % (INDEX_ROUTE, p))
    index = responses[INDEX_ROUTE]
    if not isinstance(index, dict):
        raise PackError("%s 响应不是对象：%s" % (INDEX_ROUTE, p))
    if not index:
        # 空基线会让缺键/类型漂移检查全部空转（83 键校验被静默关闭），拒绝。
        raise PackError("Index/index 基线为空（samples.json 损坏？），"
                        "拒绝以 0 键基线做校验：%s" % p)
    return index


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _type_drift(base_val, live_val):
    """标量类型漂移：基线 str vs 现值 number → ("error",…)；反向 → ("warning",…)。"""
    if isinstance(base_val, str) and _is_number(live_val):
        return "error", "数值必须保持字符串（基线 str，现值 %s）" % type(live_val).__name__
    if _is_number(base_val) and isinstance(live_val, str):
        return "warning", "基线为数值、现值为字符串（反向漂移）"
    return None


def validate_l1(l1_obj, baseline: dict, server_dir) -> tuple:
    """返回 (errors, warnings)。errors 非空 → 打包/校验失败。"""
    errors, warnings = [], []
    if not isinstance(l1_obj, dict):
        return ["l1.json 顶层不是对象"], warnings

    ui = l1_obj.get("user_info")
    if not isinstance(ui, dict) or not ui.get("id"):
        errors.append("l1 缺 user_info.id（账号 id 权威）")
    elif not isinstance(ui["id"], str):
        errors.append("user_info.id 必须是字符串（数值保持字符串），实际 %r"
                      % (ui["id"],))

    base_keys = list(baseline)
    missing = [k for k in base_keys if k not in l1_obj]
    if missing:
        errors.append("缺官方基线键 %d 个：%s" % (len(missing), ", ".join(missing)))

    for key, base_val in baseline.items():
        live_val = l1_obj.get(key)
        drift = _type_drift(base_val, live_val)
        if drift:
            kind, msg = drift
            (errors if kind == "error" else warnings).append("%s：%s" % (key, msg))

    base_ui = baseline.get("user_info")
    if isinstance(base_ui, dict) and isinstance(ui, dict):
        for key, base_val in base_ui.items():
            live_val = ui.get(key)
            drift = _type_drift(base_val, live_val)
            if drift:
                kind, msg = drift
                (errors if kind == "error" else warnings).append(
                    "user_info.%s：%s" % (key, msg))

    warnings.extend(_stc_item_warnings(l1_obj, server_dir))
    return errors, warnings


def _stc_item_warnings(l1_obj, server_dir) -> list:
    """item_with_user_info 行的 item_id 对照 stc/item_ids.json；缺失只告警。

    表文件缺失/损坏时不产生告警（本环境表可能不全）。
    """
    p = Path(server_dir) / ITEM_IDS_RELPATH
    try:
        ids_raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return []
    known = set(str(x) for x in ids_raw) if isinstance(ids_raw, list) else set()
    if not known:
        return []
    rows = l1_obj.get("item_with_user_info")
    if not isinstance(rows, list):
        return []
    missing = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        iid = row.get("item_id")
        if iid is None:
            continue
        if str(iid) not in known and str(iid) not in missing:
            missing.append(str(iid))
    if not missing:
        return []
    head = ", ".join(missing[:_STC_WARN_LIMIT])
    more = "" if len(missing) <= _STC_WARN_LIMIT else " …（共 %d 个）" % len(missing)
    return ["STC 缺失 item_id（仅告警）：%s%s" % (head, more)]


def validate_pack_l1(l1_bytes: bytes, server_dir) -> tuple:
    """便捷入口：l1 字节 → (errors, warnings)。"""
    from .contract import parse_json_bytes
    l1_obj = parse_json_bytes(l1_bytes, L1_PATH)
    baseline = compute_baseline(server_dir)
    return validate_l1(l1_obj, baseline, server_dir)
