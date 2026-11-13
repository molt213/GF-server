"""从官方 Index/index 直拉完整玩家数据，转成私服 l1。

和 live.py 的分工：
  * live.py 拉 4 个**补充**接口（邮件/好友/排行/活动），主体仍靠本地存档；
  * 本模块拉 Index/index **全量 83 键**，再用内置模板补齐私服专有的 32 键，
    从零生成一份完整 l1，不需要旁边有私服目录。
"""
from __future__ import annotations

import copy
import json
import time
import urllib.parse
from pathlib import Path

from . import envelope
from .contract import PackError
from .live import BASE_PATH, HOST, _strip_hash, assert_public_host

INDEX_ROUTE = "Index/index"
MAIL_ROUTE = "Index/getMailList"
FRIEND_ROUTE = "Friend/list"
GET_UID_ROUTE = "Index/getUidPC"
TEMPLATE_NAME = "official_template.json"


def bundle_dir() -> Path:
    """内置数据的目录。

    PyInstaller onefile 下 `__file__` 指向 `_MEIPASS` 里的副本，可用；
    但用 `sys._MEIPASS` 更明确 —— 防止某些布局下 `__file__` 是相对路径。
    """
    import sys as _sys
    meipass = getattr(_sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass) / "savepack"
    return Path(__file__).resolve().parent


def template_path() -> Path:
    return bundle_dir() / TEMPLATE_NAME


def load_template() -> dict:
    """内置模板：32 个私服专有键的默认值（内容表照搬，进度类清零）。"""
    p = template_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PackError("内置模板缺了或坏了：%s（%s）" % (p, exc)) from exc
    if not isinstance(data, dict) or not data:
        raise PackError("内置模板是空的：%s" % p)
    return data


def session_from_form(form: bytes, gateway_ip: str, host: str = None) -> dict:
    """把抓包里的 getUidPC 表单**改掉 req_id** 后重放，换 uid/sign。

    不能原样重放：服务端按 req_id 去重，同一个 req_id 再来一次会被拒。
    ticket 本身是长期凭据（15 小时级），换个 req_id 就能用。

    host 是这次登录实际用的网关域名（各分区不同，见 live.detect_host）；
    Host 头必须与它一致，否则服务端的分区路由会拒。
    """
    from urllib.parse import parse_qsl, urlencode

    host = host or HOST
    pairs = parse_qsl(form.decode("latin-1"), keep_blank_values=True)
    names = {k for k, _ in pairs}
    if not {"openid", "ticket"} <= names:
        raise PackError("抓到的表单不像 getUidPC（字段：%s）" % sorted(names))
    req_id = "%d%05d" % (int(time.time()), 1)
    body = urlencode([(k, req_id if k == "req_id" else v) for k, v in pairs])
    status, raw = _post_via_ip(gateway_ip, GET_UID_ROUTE, body, host=host)
    if status != 200:
        raise PackError("getUidPC HTTP %s（票据可能过期，重新抓一次）" % status)
    text = _strip_hash(raw.decode("utf-8", "replace"))
    plain = envelope.decode(text, envelope.QUEUE_KEY)
    if not plain:
        raise PackError("登录响应解不开：%r" % text[:160])
    try:
        obj = json.loads(plain.decode("utf-8"))
    except ValueError as exc:
        raise PackError("登录响应不是合法 JSON：%s" % exc) from exc
    uid = str(obj.get("uid") or "")
    sign = str(obj.get("sign") or "")
    if not uid or not sign:
        raise PackError("登录响应缺 uid/sign：%s" % sorted(obj))
    return {"uid": uid, "sign": sign, "host": host}


def _post_via_ip(ip: str, route: str, body: str, timeout: int = 120,
                 host: str = None):
    """用 IP 直连网关（Host 头仍写域名）。

    拉数据时 hosts 可能还指着 127.0.0.1（为了让游戏继续正常登录），
    所以不能走域名解析；这里直接打到已校验过的公网 IP。

    注意不能调 `assert_public_host(HOST)` —— 它会解析域名，此刻解析结果
    正是 127.0.0.1，会把自己拦掉。改为校验传入的 IP 本身。
    """
    import http.client
    import ipaddress as _ip

    target = _ip.ip_address(ip)
    if (target.is_private or target.is_loopback or target.is_link_local
            or target.is_reserved or target.is_multicast
            or target.is_unspecified):
        raise PackError("目标不是公网地址，拒绝连接：%s" % ip)

    conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
    try:
        conn.request("POST", BASE_PATH + route, body, {
            "Host": host or HOST,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.36f1",
            "User-Agent": ("UnityPlayer/2018.4.36f1 "
                           "(UnityWebRequest/1.0, libcurl/7.52.0-DEV)"),
        })
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _call(session: dict, route: str, payload: str, seq: int, gateway_ip: str):
    """POST 一个业务接口，返回 (解密后的对象, 原始响应字节数)。"""
    uid, sign = session["uid"], session["sign"]
    enc = envelope.encode_bytes(payload.encode("utf-8"), sign)
    req_id = "%d%05d" % (int(time.time()), seq % 100000)
    body = urllib.parse.urlencode(
        {"uid": uid, "outdatacode": enc, "req_id": req_id})
    try:
        status, raw = _post_via_ip(gateway_ip, route, body,
                                   host=session.get("host"))
    except PackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PackError("%s 请求失败：%s" % (route, exc)) from exc
    if status != 200:
        raise PackError("%s HTTP %s" % (route, status))
    text = _strip_hash(raw.decode("utf-8", "replace"))
    plain = envelope.decode(text, sign, grace=300)
    if not plain:
        raise PackError("%s 响应解不开（sign 过期或响应异常）：%r"
                        % (route, text[:120]))
    try:
        obj = json.loads(plain.decode("utf-8"))
    except ValueError as exc:
        raise PackError("%s 响应不是合法 JSON：%s" % (route, exc)) from exc
    return obj, len(raw)


def pull_index(session: dict, gateway_ip: str):
    """拉 Index/index 全量（官方 83 键）。"""
    obj, size = _call(session, INDEX_ROUTE, "{}", 1, gateway_ip)
    if not isinstance(obj, dict):
        raise PackError("Index/index 响应不是对象")
    return obj, size


def pull_mail(session: dict, gateway_ip: str):
    """拉邮件列表（可选；失败不影响主流程，调用方决定）。"""
    obj, _size = _call(session, MAIL_ROUTE, "{}", 2, gateway_ip)
    return obj


def pull_friends(session: dict, gateway_ip: str):
    """拉好友列表（可选；抓包里没有时的兜底）。

    好友不在 Index/index 的 83 键里（那儿的 friend_with_user_info 官方
    本来就是空表），必须单独请求。只读、只发一次。
    """
    obj, _size = _call(session, FRIEND_ROUTE, "{}", 3, gateway_ip)
    return obj


# 官方这几个业务接口的响应里，有些字段名和私服 l1 **完全一致** ——
# 私服的 handler 就是照官方实抓样本实现的（见 server/handlers.py 里
# dorm_info / battlepass_index 的注释）。所以拿到就能直接覆盖模板默认值，
# 不需要任何字段映射。Index/index 的 83 键不含这些，必须单独请求。
EXTRA_PULLS = (
    ("Friend/dormInfo", '{"furniture_data":true}'),   # 家具（宿舍/收纳库全用它）
    ("Battlepass/index", "{}"),                       # 前线协议
    ("Daily/index", "{}"),                            # 灰域探查
    ("Sangvis/duplicateIndex", "{}"),                 # 融合演习
    ("Chess/index", "{}"),                            # 兵棋
    ("Dorm/spare_name_list", '{"user_id":"%s"}'),     # 备用宿舍房名（%s = uid）
)

# 只认这三条里「同名同构」的键。Chess/Sangvis 的响应结构和 l1 键不同
# （chess_info/team_list vs chess_team/chess_ticket_daily），不硬塞。
EXTRA_DIRECT_KEYS = {
    "Friend/dormInfo": ("furniture_with_user_info",),
    "Battlepass/index": ("battlepass_with_user", "battlepass_pt_item"),
    "Daily/index": ("daily_status_with_user_info",),
}


def _call_any(session: dict, route: str, payload: str, seq: int, gateway_ip: str):
    """同 `_call`，但响应是明文 JSON 时也能解（Friend/Dorm 族走明文）。"""
    uid, sign = session["uid"], session["sign"]
    enc = envelope.encode_bytes(payload.encode("utf-8"), sign)
    req_id = "%d%05d" % (int(time.time()), seq % 100000)
    body = urllib.parse.urlencode(
        {"uid": uid, "outdatacode": enc, "req_id": req_id})
    try:
        status, raw = _post_via_ip(gateway_ip, route, body,
                                   host=session.get("host"))
    except PackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PackError("%s 请求失败：%s" % (route, exc)) from exc
    if status != 200:
        raise PackError("%s HTTP %s" % (route, status))
    text = raw.decode("utf-8", "replace")
    plain = envelope.decode(_strip_hash(text), sign, grace=300)
    if plain:
        try:
            return json.loads(plain.decode("utf-8")), len(raw)
        except (ValueError, UnicodeDecodeError):
            pass
    try:
        return json.loads(text), len(raw)
    except ValueError as exc:
        raise PackError("%s 响应既不是信封也不是明文 JSON：%r"
                        % (route, text[:120])) from exc


def pull_extra(session: dict, gateway_ip: str) -> dict:
    """拉 EXTRA_PULLS 里的业务接口，返回 {route: 响应对象}。

    单个失败只跳过它自己 —— 这几条都是「有比没有好」的补充数据，
    不能因为它们失败就整个导出失败。
    """
    out = {}
    uid = str(session.get("uid") or "")
    for i, (route, payload) in enumerate(EXTRA_PULLS):
        body = payload % uid if "%s" in payload else payload
        try:
            obj, _size = _call_any(session, route, body, 4 + i, gateway_ip)
        except PackError:
            continue
        if isinstance(obj, (dict, list)):
            out[route] = obj
    return out


def derive_local(l1: dict) -> list:
    """从官方 83 键**本地推算**私服的内部索引键（不额外请求）。

    依据：私服的 `_*_pending` 只是「哪些槽正在建造」的索引，官方
    `develop_*_act_info` 每行本来就带 `build_slot` + 产物 id，语义一一对应。
    `furniture_id_seq` 同理 = 已用实例 id 的最大值（私服新建时取 max+1）。
    """
    applied = []

    act = l1.get("develop_act_info")
    if isinstance(act, list):
        pend = {}
        for row in act:
            if not isinstance(row, dict):
                continue
            slot = str(row.get("build_slot") or "")
            gun = str(row.get("gun_id") or "0")
            if slot and gun not in ("0", ""):
                pend[slot] = gun
        l1["_build_pending"] = pend
        applied.append("_build_pending")

    eact = l1.get("develop_equip_act_info")
    if isinstance(eact, dict):
        pend = {}
        for slot, row in eact.items():
            if not isinstance(row, dict):
                continue
            eq = str(row.get("equip_id") or "0")
            if eq not in ("0", ""):
                pend[str(slot)] = eq
        l1["_equip_build_pending"] = pend
        applied.append("_equip_build_pending")

    fact = l1.get("develop_fairy_act_info")
    if isinstance(fact, list):
        pend = {}
        for row in fact:
            if not isinstance(row, dict):
                continue
            slot = str(row.get("build_slot") or "")
            fid = str(row.get("fairy_id") or "0")
            if slot and fid not in ("0", ""):
                pend[slot] = fid
        l1["_fairy_build_pending"] = pend
        applied.append("_fairy_build_pending")

    furn = l1.get("furniture_with_user_info")
    if isinstance(furn, list) and furn:
        ids = []
        for row in furn:
            if isinstance(row, dict):
                try:
                    ids.append(int(row.get("id") or 0))
                except (TypeError, ValueError):
                    pass
        if ids:
            l1["furniture_id_seq"] = max(ids)
            applied.append("furniture_id_seq")

    ssa = l1.get("squad_skill_act_info")
    if isinstance(ssa, list) and ssa:
        slots = {}
        for row in ssa:
            if isinstance(row, dict):
                slot = str(row.get("slot") or "")
                if slot:
                    slots[slot] = row
        if slots:
            l1["squad_skill_slot"] = slots
            applied.append("squad_skill_slot")

    return applied


def to_local_from_responses(responses: dict) -> dict:
    """把**结构不同**的业务响应转成私服 l1 键。

    每条都只做字段搬运/改名，不补默认值 —— 响应里没有的键就不产出，
    让模板值保留。
    """
    out = {}

    # 兵棋：chess_info → chess_ticket_daily / chess_gasha_acquired，
    #       team_list → chess_team（l1 是 {team_id: [行...]}）
    chess = responses.get("Chess/index")
    if isinstance(chess, dict):
        info = chess.get("chess_info")
        if isinstance(info, dict):
            num = info.get("ticket_daily_num")
            if num is not None:
                out["chess_ticket_daily"] = {
                    "num": str(num),
                    "time": str(info.get("ticket_daily_refresh_time") or 0)}
            acq = info.get("acquired_bonus")
            if isinstance(acq, str) and acq.strip():
                vals = sorted({int(x) for x in acq.split(",")
                               if x.strip().lstrip("-").isdigit()})
                if vals:
                    out["chess_gasha_acquired"] = vals
        teams = chess.get("team_list")
        if isinstance(teams, list) and teams:
            grouped = {}
            for row in teams:
                if isinstance(row, dict):
                    grouped.setdefault(str(row.get("team_id") or "0"),
                                       []).append(row)
            if grouped:
                out["chess_team"] = grouped

    # 融合演习：根键 {"1"/"2"/"3": {"win_counter": N}} → sangvis_duplicate_win
    dup = responses.get("Sangvis/duplicateIndex")
    if isinstance(dup, dict):
        wins = {}
        for k in ("1", "2", "3"):
            v = dup.get(k)
            if isinstance(v, dict) and "win_counter" in v:
                try:
                    wins[k] = int(v["win_counter"])
                except (TypeError, ValueError):
                    pass
        if wins:
            out["sangvis_duplicate_win"] = wins

    # 宿舍：info.dorm_id → dorm_build_coin_current_room
    dorm = responses.get("Friend/dormInfo")
    if isinstance(dorm, dict):
        info = dorm.get("info")
        if isinstance(info, dict) and info.get("dorm_id"):
            out["dorm_build_coin_current_room"] = str(info["dorm_id"])

    # 备用宿舍：响应是数组 [{dorm_spare_id, dorm_name}] → l1 的字典
    spare = responses.get("Dorm/spare_name_list")
    if isinstance(spare, list) and spare:
        rows = {}
        for row in spare:
            if isinstance(row, dict) and row.get("dorm_spare_id"):
                sid = str(row["dorm_spare_id"])
                rows[sid] = {"dorm_spare_id": sid,
                             "dorm_name": str(row.get("dorm_name") or sid)}
        if rows:
            out["dorm_spare_info"] = rows

    return out


def merge_extra(l1: dict, responses: dict) -> list:
    """把响应里「和 l1 同名同构」的字段覆盖进 l1，返回被覆盖的键名列表。

    只认 EXTRA_DIRECT_KEYS 白名单。其余字段一律不动 —— 不同结构的业务
    字段硬塞进 l1 只会让客户端解析崩，宁可保留模板默认值。
    """
    applied = []
    for route, keys in EXTRA_DIRECT_KEYS.items():
        obj = responses.get(route)
        if not isinstance(obj, dict):
            continue
        for key in keys:
            value = obj.get(key)
            if isinstance(value, (list, dict)) and value:
                l1[key] = value
                applied.append(key)
    # 结构不同的业务响应走专门映射（兵棋 / 融合演习 / 宿舍）
    for key, value in to_local_from_responses(responses).items():
        l1[key] = value
        applied.append(key)
    return applied


def _as_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def friends_to_private(obj) -> list:
    """官方 Friend/list 响应 → 私服 server/data/friends.json 的行数组。

    只搬 Friend/list 本来就带的字段。名片/梯队/妖精详情不在这条响应里，
    留空并标 `detail_known=False` —— 与 round17 的口径一致：不用 0 或
    5061 配置去造合成数据，避免把编的东西当好友真实数据。
    """
    if not isinstance(obj, dict):
        return []
    rows = obj.get("list") or obj.get("friend_list") or obj.get("user_list") or []
    if not isinstance(rows, list):
        return []
    out = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        uid = _as_int(row.get("f_userid") or row.get("uid") or row.get("user_id"))
        if not uid or uid in seen:
            continue
        seen.add(uid)
        out.append({
            "uid": uid,
            "f_userid": uid,
            "zone_id": str(row.get("f_zoneid") or row.get("zone_id") or ""),
            "name": str(row.get("name") or ""),
            "lv": _as_int(row.get("lv")) or 1,
            "headpic_id": _as_int(row.get("headpic_id")),
            "frame_id": _as_int(row.get("frame_id")),
            "last_login": _as_int(row.get("homepage_time") or row.get("last_login")),
            "dorm_id": _as_int(row.get("dorm_id")),
            "max_dorm": _as_int(row.get("max_dorm")) or 10,
            "gender": _as_int(row.get("gender")),
            "end_time": _as_int(row.get("end_time")),
            "gun_collect": _as_int(row.get("gun_collect")),
            "furniture_collect": _as_int(row.get("furniture_collect")),
            "is_return_user": _as_int(row.get("is_return_user")),
            "is_vehicle_visit": _as_int(row.get("is_vehicle_visit")),
            "detail_known": False,
        })
    return out


def to_private(official: dict, template: dict) -> dict:
    """官方 83 键 + 模板 32 键 → 私服 l1。

    两边的键不重叠（官方 83 键全部也存在于私服 l1），这里仍然用
    「模板打底、官方覆盖」的顺序，保证官方值优先。
    """
    out = copy.deepcopy(template)
    for key, value in official.items():
        out[key] = copy.deepcopy(value)
    ui = out.get("user_info")
    if isinstance(ui, dict):
        for key in ("id", "name"):
            if key in ui and not isinstance(ui[key], str):
                ui[key] = str(ui[key])
    # 黑卡赠送标记：模板是从私服 l1 原样切出来的，值是 1（该号已经领过）。
    # 导出的包是给「另一个号」用的，必须清零 —— 否则导入后私服看到标记
    # 已存在，不会再补发首次登录那张黑卡。
    out["blackcard_granted"] = 0
    return out


def write_local_server(root, l1: dict, mail=None, friends=None) -> Path:
    """把 l1（和可选邮件/好友）落成一个 savepack 认识的 server 目录。"""
    srv = Path(root) / "server"
    player = srv / "content" / "player"
    player.mkdir(parents=True, exist_ok=True)
    (player / "l1.json").write_text(
        json.dumps(l1, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8")
    if mail is not None:
        (player / "mail.json").write_text(
            json.dumps(mail, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")
    if friends is not None:
        data = srv / "data"
        data.mkdir(parents=True, exist_ok=True)
        (data / "friends.json").write_text(
            json.dumps(friends, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")
    return srv
