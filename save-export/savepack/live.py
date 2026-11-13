"""local+b：live 直拉 B 数据。

流程（实现参考 .tmp/cap/take_body.py 与 pull_b.py，本模块重写、不 import）：
  1. 从 pcapng 取第一条 POST /Index/getUidPC 请求的完整表单（openid/sid/ticket/req_id）；
  2. 把表单原样 POST 到官方网关 getUidPC，用 "yundoudou" 解出 uid/sign；
  3. 依次拉 Friend/list、Index/getMailList、Index/rank、Index/getEventInfo，
     每次 req_id 必须不同（服务端按它去重）。

安全红线（项目约定）：
  * 只允许 http/https；
  * host 必须命中白名单，且 DNS 解析结果不得是环回/私有/保留地址；
  * 只调 getXxx/list 读接口，写接口一律不发（端点表写死、无参数化入口）；
  * sign/password 不落盘、不打印——表单凭据只在内存，错误信息不带值。
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.parse
from pathlib import Path

from . import envelope, tcpflow
from . import pcapng as _pcapng
from .contract import PackError

HOST = "gfcn-game.gw.merge.sunborngame.com"
ALLOW_HOSTS = {HOST}
QUEUE_KEY = "yundoudou"          # 登录前队列响应的固定密钥（见 server/gfcrypto.py）
GET_UID_ROUTE = "Index/getUidPC"
INDEX_ROUTE = "Index/index"
FRIEND_ROUTE = "Friend/list"
BASE_PATH = "/index.php/1000/"

# 只读端点表（payload 与 pull_b.py 一致；没有写接口，也不提供传参口子）
PULLS = (
    ("Friend/list", "{}"),
    ("Index/getMailList", "{}"),
    ("Index/rank", '{"type":1,"index":0,"length":20,"sub_type":"0","condition":0}'),
    ("Index/getEventInfo", "{}"),
)
_PULL_KEY = {
    "Friend/list": "friends",
    "Index/getMailList": "mail",
    "Index/rank": "rank",
    "Index/getEventInfo": "event",
}

_TIMEOUT = 30
_UA = ("UnityPlayer/2018.4.36f1 "
       "(UnityWebRequest/1.0, libcurl/7.52.0-DEV)")


# ---------------------------------------------------------------- 安全检查
def assert_public_host(host: str) -> None:
    """host 白名单 + DNS 解析结果必须全是公网地址。"""
    if host not in ALLOW_HOSTS:
        raise PackError("host 不在白名单：%r" % host)
    try:
        infos = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PackError("DNS 解析失败 %s：%s" % (host, exc)) from exc
    if not infos:
        raise PackError("DNS 解析无结果：%s" % host)
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise PackError("host 解析到非公网地址，拒绝连接：%s" % ip)


def _post(url: str, body: str) -> tuple:
    """只允许 http/https；host 再过一次白名单。返回 (status, 原始字节)。"""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise PackError("只允许 http/https：%r" % parts.scheme)
    assert_public_host(parts.hostname)
    port = parts.port or (80 if parts.scheme == "http" else 443)
    if parts.scheme == "http":
        conn = http.client.HTTPConnection(parts.hostname, port, timeout=_TIMEOUT)
    else:
        conn = http.client.HTTPSConnection(parts.hostname, port, timeout=_TIMEOUT)
    try:
        conn.request("POST", parts.path, body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "User-Agent": _UA,
                              "Connection": "close"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


# ---------------------------------------------------------------- 抓包解析
_B64_RE = re.compile(rb"#[A-Za-z0-9+/=]{40,}")
_HTTP_PORTS = (80, 8080, 8443)
_RAW_LIMIT = 4 * 1024 * 1024


def scan_capture(cap_path) -> dict:
    """读 pcapng → 按 TCP 连接重组 → HTTP 消息 + 诊断统计。

    与老实现的区别：跨 TCP 段的请求/响应能拼回来、VLAN 和裸 IP 帧能解、
    pktmon 多组件重复包按 seq 自动去重。
    """
    cap = Path(cap_path).expanduser().resolve()
    reader = _pcapng.Reader(cap)
    flows: dict = {}
    stats = {
        "packets": 0,
        "by_linktype": {},
        "drop_l2": 0,
        "drop_ip": 0,
        "drop_proto": 0,
        "drop_tcp": 0,
        "drop_port": 0,
        "truncated": 0,
        "other_ports": {},
    }

    for pkt in reader.packets():
        stats["packets"] += 1
        stats["by_linktype"][pkt.linktype] = \
            stats["by_linktype"].get(pkt.linktype, 0) + 1

        got = tcpflow.ip_packet(pkt.data, pkt.linktype)
        if not got:
            stats["drop_l2"] += 1
            continue
        parsed = tcpflow.ip_payload(got[1])
        if not parsed:
            stats["drop_ip"] += 1
            continue
        src, dst, proto, ip_data, truncated = parsed
        if proto != 6:
            stats["drop_proto"] += 1
            continue
        seg = tcpflow.tcp_segment(ip_data)
        if not seg:
            stats["drop_tcp"] += 1
            continue
        sport, dport, seq, _flags, payload = seg
        if truncated:
            stats["truncated"] += 1

        if dport in _HTTP_PORTS:
            key = (src, sport, dst, dport)
            direction = "c2s"
        elif sport in _HTTP_PORTS:
            key = (dst, dport, src, sport)
            direction = "s2c"
        else:
            stats["drop_port"] += 1
            port = max(sport, dport)
            stats["other_ports"][port] = \
                stats["other_ports"].get(port, 0) + 1
            continue

        flow = flows.get(key)
        if flow is None:
            flow = {"c2s": tcpflow.Direction(), "s2c": tcpflow.Direction()}
            flows[key] = flow
        flow[direction].add(seq, payload)

    requests: list = []
    responses: list = []
    pairs: list = []
    raw_blobs: list = []
    rows: list = []
    route = GET_UID_ROUTE.encode()

    for (sip, sport, dip, dport), flow in flows.items():
        c2s_runs = flow["c2s"].runs()
        s2c_runs = flow["s2c"].runs()
        reqs = [m for _s, buf in c2s_runs for m in tcpflow.iter_messages(buf)]
        resps = [m for _s, buf in s2c_runs for m in tcpflow.iter_messages(buf)]
        requests.extend(reqs)
        responses.extend(resps)
        for i, req in enumerate(reqs):
            if i < len(resps):
                pairs.append((req, resps[i]))
        for _seq, buf in c2s_runs + s2c_runs:
            stats.setdefault("raw_route_hits", 0)
            stats["raw_route_hits"] += buf.count(route)
            if 64 < len(buf) <= _RAW_LIMIT and b"#" in buf:
                raw_blobs.append(buf)
        rows.append({
            "client": "%s:%d" % (sip, sport),
            "server": "%s:%d" % (dip, dport),
            "up": sum(len(b) for _s, b in c2s_runs),
            "down": sum(len(b) for _s, b in s2c_runs),
            "requests": len(reqs),
            "responses": len(resps),
        })

    seen = sum(1 for req in requests if GET_UID_ROUTE in (req.target or ""))
    return {
        "path": cap,
        "reader": reader.summary(),
        "interfaces": reader.interface_summary(),
        "stats": stats,
        "flows": rows,
        "requests": requests,
        "responses": responses,
        "pairs": pairs,
        "raw": raw_blobs,
        "getuidpc_seen": seen,
        "getuidpc_raw": stats.get("raw_route_hits", 0),
    }


def _decode_with_key(body: bytes, headers, key: str):
    """按信封解一段响应体，返回解析后的 JSON（失败返回 None）。"""
    if not body:
        return None
    if headers:
        body = tcpflow.maybe_ungzip(body, headers)
    text = "".join(body.decode("utf-8", "replace").split())
    if text.startswith("#"):
        text = text[1:]
    plain = envelope.decode(text, key)
    if not plain:
        return None
    try:
        return json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _decode_any(body: bytes, headers, key=None):
    """先按明文 JSON 解，再按信封解（给了 key 才试）。"""
    if not body:
        return None
    if headers:
        body = tcpflow.maybe_ungzip(body, headers)
    text = body.decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, (dict, list)):
        return obj
    if key:
        return _decode_with_key(body, None, key)
    return None


def _friend_rows(obj):
    """从响应对象里认出好友行数组（认不出返回 None）。"""
    if not isinstance(obj, dict):
        return None
    for key in ("list", "friend_list", "user_list"):
        rows = obj.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        first = rows[0]
        if not isinstance(first, dict):
            continue
        if any(k in first for k in ("f_userid", "f_zoneid", "headpic_id")):
            return rows
        if "name" in first and "lv" in first:
            return rows
    return None


def find_friend_list_response(scan, sign=None):
    """抓包 → (响应对象, 来源说明)。取不到返回 (None, None)。

    好友列表走独立的 `Friend/list`，**不在 Index/index 的 83 键里**
    （那边的 friend_with_user_info 官方本来就是空表）。客户端只在打开
    好友页时发这条请求，所以抓包里有没有取决于登录后点没点好友页。

    响应通常是明文 JSON；也按信封兜一层，防官方以后包起来。
    抓包里没有时，调用方可以用会话 sign 直拉（official.pull_friends）。
    """
    for req, resp in scan["pairs"]:
        if FRIEND_ROUTE in (req.target or ""):
            obj = _decode_any(resp.body, resp.headers, sign)
            if _friend_rows(obj):
                return obj, "抓包中的 %s 响应" % FRIEND_ROUTE

    for resp in scan["responses"]:
        obj = _decode_any(resp.body, resp.headers, sign)
        if _friend_rows(obj):
            return obj, "抓包中的响应（路由未配对）"

    return None, None


def _decode_login(body: bytes, headers=None):
    """把一段响应体按登录信封解，成功返回 {uid, sign}，否则 None。"""
    obj = _decode_with_key(body, headers, QUEUE_KEY)
    if not isinstance(obj, dict):
        return None
    uid = str(obj.get("uid") or "")
    sign = str(obj.get("sign") or "")
    if not uid or not sign:
        return None
    return {"uid": uid, "sign": sign}


def find_uid_response(cap_path, scan=None):
    """抓包 → (session, 来源说明)。三层兜底，任一成功即返回。

    第一层走 HTTP 配对（最准），第二层不看路由（防配对错位），
    第三层直接在原始字节里正则扫 `#<base64>`（完全不依赖解析正确性）。
    """
    scan = scan or scan_capture(cap_path)

    for req, resp in scan["pairs"]:
        if GET_UID_ROUTE in (req.target or ""):
            got = _decode_login(resp.body, resp.headers)
            if got:
                return got, "抓包中的 %s 响应" % GET_UID_ROUTE

    for resp in scan["responses"]:
        got = _decode_login(resp.body, resp.headers)
        if got:
            return got, "抓包中的响应（路由未配对）"

    for blob in scan["raw"]:
        for match in _B64_RE.finditer(blob):
            got = _decode_login(match.group(0))
            if got:
                return got, "抓包原始字节（盲扫）"

    return None, None


def find_index_response(cap_path, sign: str, scan=None):
    """从抓包里找 Index/index 的响应，用会话 sign 解开。

    这是 `official.pull_index` 失败时的兜底：客户端登录时自己拉过一次，
    那份响应就在抓包里，不需要再请求服务器。
    """
    scan = scan or scan_capture(cap_path)

    def plausible(obj) -> bool:
        # Index/index 是 83 键的大对象；其它接口多半是 list 或小 dict
        return isinstance(obj, dict) and len(obj) >= 40

    for req, resp in scan["pairs"]:
        if INDEX_ROUTE in (req.target or ""):
            obj = _decode_with_key(resp.body, resp.headers, sign)
            if plausible(obj):
                return obj

    for resp in scan["responses"]:
        if len(resp.body) < 4096:          # 小响应不可能是全量索引
            continue
        obj = _decode_with_key(resp.body, resp.headers, sign)
        if plausible(obj):
            return obj
    return None


def diagnose_text(scan: dict) -> str:
    """把扫描结果写成人类可读的诊断（失败时贴出来就能定位）。"""
    stats = scan["stats"]
    lines = ["抓包诊断：%s" % scan["reader"],
             "  接口：%s" % scan["interfaces"]]
    if stats["by_linktype"]:
        lines.append("  linktype：" + "，".join(
            "%s ×%d" % (_pcapng.linktype_name(lt), n)
            for lt, n in sorted(stats["by_linktype"].items())))
    lines.append("  包数 %d；丢弃：链路层 %d、IP %d、非 TCP %d、TCP 头 %d、"
                 "端口不相关 %d；IP 分片 %d"
                 % (stats["packets"], stats["drop_l2"], stats["drop_ip"],
                    stats["drop_proto"], stats["drop_tcp"],
                    stats["drop_port"], stats["truncated"]))
    if stats["other_ports"]:
        top = sorted(stats["other_ports"].items(), key=lambda kv: -kv[1])[:5]
        lines.append("  其它端口前 5：" + "，".join(
            "%d ×%d" % (port, n) for port, n in top))
    lines.append("  TCP 流 %d 条" % len(scan["flows"]))
    for row in scan["flows"][:6]:
        lines.append("    %s → %s  上行 %.1f KB / 下行 %.1f KB  请求 %d 响应 %d"
                     % (row["client"], row["server"], row["up"] / 1024.0,
                        row["down"] / 1024.0, row["requests"],
                        row["responses"]))
    lines.append("  HTTP：请求 %d 条、响应 %d 条"
                 % (len(scan["requests"]), len(scan["responses"])))
    for req in scan["requests"][:8]:
        lines.append("    %s %s" % (req.method, req.target))
    lines.append("  %s：路由命中 %d 次、原始字节出现 %d 次"
                 % (GET_UID_ROUTE, scan["getuidpc_seen"],
                    scan["getuidpc_raw"]))
    return "\n".join(lines)


def diagnose(cap_path) -> str:
    """读一遍抓包，返回诊断文本（不抛错）。"""
    try:
        return diagnose_text(scan_capture(cap_path))
    except PackError as exc:
        return "[诊断失败] %s" % exc


def _form_summary(form: bytes) -> dict:
    """表单字段名 → 值长度（只给日志用，值本身不出现在任何输出里）。"""
    out = {}
    for kv in form.decode("latin-1").split("&"):
        name, _, val = kv.partition("=")
        out[name] = len(val)
    return out


def first_getuidpc_form(cap_path) -> tuple:
    """抓包 → (第一条 getUidPC 表单体, 字段摘要)。

    表单含 openid/sid/ticket 等凭据：只在内存传递，不落盘、不打印值。
    HTTP 头体跨多个 TCP 段、带 VLAN 标签、裸 IP 帧都能拼出来。
    """
    scan = scan_capture(cap_path)
    for req in scan["requests"]:
        if GET_UID_ROUTE in (req.target or "") and req.body:
            return req.body, _form_summary(req.body)
    raise PackError("抓包里没有 %s 请求表单。\n%s"
                    % (GET_UID_ROUTE, diagnose_text(scan)))


# ---------------------------------------------------------------- 会话与直拉
def _load_gfcrypto(server_dir):
    """server/gfcrypto.py 提供鉴权信封实现（import，不复制算法）。"""
    sd = Path(server_dir)
    if not (sd / "gfcrypto.py").is_file():
        raise PackError("server 目录下没有 gfcrypto.py：%s" % sd)
    if str(sd) not in sys.path:
        sys.path.insert(0, str(sd))
    try:
        import gfcrypto  # noqa: E402  （依赖 server/state.py，均为只读使用）
    except Exception as exc:  # noqa: BLE001
        raise PackError("导入 server/gfcrypto 失败：%s" % exc) from exc
    return gfcrypto


def _strip_hash(text: str) -> str:
    return text[1:] if text.startswith("#") else text


def fetch_session(cap_path, server_dir) -> dict:
    """抓包表单 → getUidPC → {"uid", "form_fields"}（sign 只留在内存）。"""
    gc = _load_gfcrypto(server_dir)
    form, summary = first_getuidpc_form(cap_path)
    assert_public_host(HOST)
    url = "http://" + HOST + BASE_PATH + GET_UID_ROUTE
    try:
        status, raw = _post(url, form.decode("latin-1"))
    except PackError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise PackError("getUidPC 请求失败：%s" % exc) from exc
    if status != 200:
        raise PackError("getUidPC HTTP %s（ticket 可能已过期，重新抓包）" % status)
    try:
        plain = gc.decode(_strip_hash(raw.decode("utf-8", "replace")), QUEUE_KEY)
        obj = json.loads(plain.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise PackError("getUidPC 响应解密失败：%s" % exc) from exc
    uid = str(obj.get("uid") or "")
    sign = str(obj.get("sign") or "")
    if not uid or not sign:
        raise PackError("getUidPC 响应缺 uid/sign（内容不落盘、不打印）")
    session = {"uid": uid, "sign": sign,
               "form_fields": summary, "http_status": status}
    return session


def pull_all(session: dict, server_dir) -> dict:
    """按端点表直拉 4 个只读接口 → B 数据 dict（req_id 每次不同）。"""
    gc = _load_gfcrypto(server_dir)
    uid, sign = session["uid"], session["sign"]
    assert_public_host(HOST)
    out = {"uid": uid, "mail": None, "friends": None, "rank": None,
           "event": None, "endpoints": []}
    base = int(time.time())
    for i, (route, payload) in enumerate(PULLS):
        enc = gc.encode_bytes(payload.encode("utf-8"), sign)
        req_id = "%d%05d" % (base, (i + 1) % 100000)   # 同秒内靠序号去重
        data = urllib.parse.urlencode(
            {"uid": uid, "outdatacode": enc, "req_id": req_id})
        url = "http://" + HOST + BASE_PATH + route
        try:
            status, raw = _post(url, data)
        except PackError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise PackError("%s 请求失败：%s" % (route, exc)) from exc
        try:
            plain = gc.decode(_strip_hash(raw.decode("utf-8", "replace")), sign)
            obj = json.loads(plain.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise PackError("%s 响应解密失败：%s" % (route, exc)) from exc
        out[_PULL_KEY[route]] = obj
        out["endpoints"].append({"route": route, "http": status,
                                 "raw_bytes": len(raw)})
    return out


def collect_b(cap_path, server_dir) -> dict:
    """local+b 完整流程：抓包 → 会话 → 四连拉。"""
    session = fetch_session(cap_path, server_dir)
    return pull_all(session, server_dir)
