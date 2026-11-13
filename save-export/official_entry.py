"""官方账号 → 私服存档（PC 端一键导出）。PyInstaller 入口。

流程：
  1. 临时把游戏网关域名指到本机，起一个反向代理
  2. 你启动游戏、正常登录 —— 代理截下 getUidPC 的 openid/sid/ticket
  3. 立刻恢复 hosts、关代理；用凭据换 uid/sign
  4. 拉 Index/index 全量（官方 83 键）
  5. 补私服专有的 32 键 → 转成私服 l1
  6. 打包成 save-<uid>-<日期>.gfsave.zip

全程只读：不调任何写接口，不改游戏文件。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from savepack import capture, live, official, proxy
from savepack.contract import PackError
from savepack.live import HOST


def _setup_console() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleTitleW("GF 官方存档导出")
    except Exception:  # noqa: BLE001
        pass


def _relaunch_as_admin() -> bool:
    """非管理员时用 UAC 重新拉起自己；成功返回 True。"""
    if proxy.is_admin():
        return False
    try:
        import ctypes
        params = subprocess.list2cmdline(sys.argv)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception:  # noqa: BLE001
        return False


def _out_dir() -> Path:
    """exe 旁边，或脚本所在目录（源码模式）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def run(from_pcap=None, keep: bool = False, use_filter: bool = True,
        gateway=None) -> int:
    out_dir = _out_dir()
    print("=" * 52)
    print("   GF 官方存档导出  →  私服可导入的 gfsave.zip")
    print("=" * 52)
    print()

    cap = None
    pcap = None
    ok = False
    try:
        if from_pcap:
            pcap = Path(from_pcap).expanduser().resolve()
            if not pcap.is_file():
                raise PackError("抓包文件不存在：%s" % pcap)
            print("[1/4] 跳过抓包，直接读：%s" % pcap)
            gateway_ip = gateway or proxy.resolve_gateway()
        else:
            print("[1/4] 准备抓包…")
            gateway_ip = gateway or proxy.resolve_gateway()
            print("      网关 %s → %s" % (HOST, gateway_ip))
            cap = capture.Capture()
            cap.start(ips=[gateway_ip], use_filter=use_filter)
            print("      pktmon 已开始抓包：%s" % cap.status_text())
            print("      （不改 hosts、不占端口）")
            print()
            print("[2/4] 现在启动游戏，登录到主界面。")
            print("      顺便点开一次「好友」页 —— 客户端会拉一次好友名册，")
            print("      抓包就能直接取到；不点也行，工具会自己补拉一次。")
            print("      做完回到这里按回车继续。")
            print("      （抓包只用来取登录凭据，出包后自动删掉）")
            print()
            try:
                input("      按回车继续… ")
            except (EOFError, KeyboardInterrupt):
                raise PackError("已取消") from None
            pcap = cap.stop()
            print("      抓包已停止：%.1f MB"
                  % (pcap.stat().st_size / 1048576.0))

        print()
        print("[3/4] 解析抓包取凭据…")
        scan = live.scan_capture(pcap)
        print("      %s" % scan["reader"])
        print("      %s" % scan["interfaces"])
        print("      包 %d、TCP 流 %d、HTTP 请求 %d / 响应 %d"
              % (scan["stats"]["packets"], len(scan["flows"]),
                 len(scan["requests"]), len(scan["responses"])))

        session, how = live.find_uid_response(pcap, scan)
        if session:
            print("      凭据来源：%s（不重放登录请求）" % how)
        else:
            print("      没找到可解的登录响应，退回表单重放…")
            try:
                form, summary = live.first_getuidpc_form(pcap)
            except PackError:
                print(live.diagnose_text(scan))
                raise
            print("      登录表单：%s" % summary)
            session = official.session_from_form(form, gateway_ip)

        # 抓包里客户端自己拉的那份 Index/index，先取出来复用（直拉失败时兜底）。
        # 注意它的 user_info.id 可能和登录响应的 uid 不同（实测两个值并不一致）：
        # 游戏里显示的是**登录响应**的 uid，所以 uid 一律以 session 为准，
        # Index/index 里那个只当内部编号。
        cached_index = live.find_index_response(pcap, session["sign"], scan)
        data_uid = str(((cached_index or {}).get("user_info") or {}).get("id") or "")
        if data_uid and data_uid != session["uid"]:
            print("      登录 uid = %s，数据内 id = %s（游戏内按登录 uid）"
                  % (session["uid"], data_uid))
        print("      账号 uid: %s" % session["uid"])

        # 好友列表不在 Index/index 的 83 键里（那边的 friend_with_user_info
        # 官方本来就是空表），必须单独取：抓包里客户端自己拉过就白拿，
        # 没有就用刚拿到的会话 sign 补拉一次（只读，只发一次）。
        friends = None
        fobj, fhow = None, None
        try:
            fobj, fhow = live.find_friend_list_response(scan, session["sign"])
        except Exception:  # noqa: BLE001
            fobj, fhow = None, None
        if fobj is None:
            try:
                fobj = official.pull_friends(session, gateway_ip)
                fhow = "自己向网关补拉了一次 %s" % live.FRIEND_ROUTE
            except PackError as exc:
                print("      好友列表拉取跳过（%s）" % exc)
        if fobj is not None:
            friends = official.friends_to_private(fobj)
        if friends:
            print("      好友 %d 人（%s）" % (len(friends), fhow))
        elif fobj is not None:
            print("      好友响应里没有可用行（%s）" % fhow)

        try:
            index, size = official.pull_index(session, gateway_ip)
        except PackError as exc:
            print("      直拉 Index/index 失败（%s），改用抓包里的响应…" % exc)
            index = cached_index or live.find_index_response(
                pcap, session["sign"], scan)
            if not index:
                raise
            size = len(json.dumps(index, ensure_ascii=False).encode("utf-8"))
            print("      （客户端登录时自己拉过，抓包里就有）")
        print("      Index/index: %d 个键，%.1f MB"
              % (len(index), size / 1048576.0))

        mail = None
        try:
            got = official.pull_mail(session, gateway_ip)
        except PackError as exc:
            print("      邮件拉取跳过（%s）" % exc)
        else:
            if isinstance(got, list):
                mail = got
                print("      邮件: %d 封" % len(got))

        # 官方 83 键之外、私服 l1 需要的补充数据（家具/前线/灰域探查）。
        # 这些只有单独的业务接口才返回，Index/index 里没有；
        # 拉到就用官方真实值覆盖模板默认值。
        extra = official.pull_extra(session, gateway_ip)
        if extra:
            print("      补充数据：%d 个接口（%s）"
                  % (len(extra), ", ".join(sorted(extra))))
        else:
            print("      补充数据：一个都没拉到（用模板默认值）")

        print()
        print("[4/4] 转换并打包…")
        template = official.load_template()
        l1 = official.to_private(index, template)
        # 游戏里显示的是登录响应（getUidPC）的 uid。Index/index 的
        # user_info.id 可能是另一个内部编号（实测两个值并不一致），
        # 这里统一成登录 uid —— 打包时 normalize 会以它为权威把行级
        # user_id 全部归一，包名也用它。
        ui = l1.get("user_info")
        if isinstance(ui, dict) and str(ui.get("id") or "") != session["uid"]:
            print("      游戏内 uid：%s（覆盖 Index/index 的 id %s）"
                  % (session["uid"], ui.get("id")))
            ui["id"] = session["uid"]
        print("      官方 %d 键 + 私服补 %d 键 = %d 键"
              % (len(index), len(template), len(l1)))
        applied = official.merge_extra(l1, extra)
        if applied:
            print("      官方补充键 %d 个：%s"
                  % (len(applied), ", ".join(applied)))
        derived = official.derive_local(l1)
        if derived:
            print("      本地推算 %d 个：%s"
                  % (len(derived), ", ".join(derived)))
        # 逐个打印实际值，方便一眼看出哪个键没被官方数据覆盖
        for key in applied + derived:
            brief = json.dumps(l1.get(key), ensure_ascii=False)
            print("        %-30s %s"
                  % (key, brief if len(brief) <= 46 else brief[:46] + "…"))
        out = _build_pack(out_dir, l1, mail, session["uid"], friends)
        ok = True
    except PackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PackError("导出阶段出错：%s" % exc) from exc
    finally:
        if cap is not None:
            kept = cap.cleanup(keep=(keep or not ok))
            if kept:
                _report_saved(kept, out_dir, failed=not ok)

    print()
    print("完成：%s" % out)
    print("  文件 %s" % _human(out.stat().st_size))
    print()
    print("把这个 zip 发到手机，在「GF 私服」里点「导入存档」选中它，")
    print("再点一次「启动」就生效。")
    return 0


def _copy_capture(src: Path, out_dir: Path):
    """把临时目录里的抓包拷到 exe 旁边，方便用户找到并发出来。"""
    import shutil
    dest = out_dir / ("GF抓包-%s.pcapng" % time.strftime("%Y%m%d-%H%M%S"))
    try:
        shutil.copy2(src, dest)
        return dest
    except OSError:
        return None


def _report_saved(src: Path, out_dir: Path, failed: bool) -> None:
    """保留抓包时打印路径；失败时再附一份诊断。"""
    dest = src
    if failed:
        copied = _copy_capture(src, out_dir)
        if copied is not None:
            dest = copied
    print()
    print("[抓包已保留] %s" % dest)
    if not failed:
        return
    print("  这个文件里有登录票据，只在本机调试用，别外传。")
    print("  离线复现：GF存档导出.exe --from-pcap \"%s\"" % dest)
    print()
    try:
        print(live.diagnose(dest))
    except Exception:  # noqa: BLE001
        pass


def _seed_validation_inputs(srv: Path) -> None:
    """补上 validate 需要的两份内置数据（83 键基线 + STC 道具 id）。"""
    here = official.bundle_dir()
    samples = srv / "samples" / "samples.json"
    samples.parent.mkdir(parents=True, exist_ok=True)
    base = json.loads((here / "official_baseline.json")
                      .read_text(encoding="utf-8"))
    samples.write_text(json.dumps(base, ensure_ascii=False, separators=(",", ":")),
                       encoding="utf-8")
    items = srv / "data" / "stc" / "item_ids.json"
    items.parent.mkdir(parents=True, exist_ok=True)
    items.write_text((here / "official_item_ids.json").read_text(encoding="utf-8"),
                     encoding="utf-8")


def _fix_hosts() -> int:
    """清理 hosts 里本工具留下的临时记录（工具被强杀后的补救）。"""
    p = proxy.hosts_file()
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print("[失败] 读不到 hosts：%s" % exc)
        return 1
    lines = raw.splitlines(True)
    kept = [line for line in lines
            if proxy.MARK not in line and proxy.HOST not in line]
    if len(kept) == len(lines):
        print("hosts 是干净的，没有被改过。")
        return 0
    try:
        p.write_text("".join(kept), encoding="utf-8")
    except OSError as exc:
        print("[失败] 写不了 hosts（要管理员权限）：%s" % exc)
        return 1
    print("已清理 hosts 里 %d 行临时记录，游戏可以正常连官方了。"
          % (len(lines) - len(kept)))
    return 0


def _build_pack(out_dir: Path, l1: dict, mail, fallback_uid: str,
                friends=None) -> Path:
    """把合并后的 l1（和可选邮件/好友）打成 gfsave.zip。"""
    tmp = Path(tempfile.mkdtemp(prefix="gfsave-official-"))
    try:
        srv = official.write_local_server(tmp, l1, mail, friends)
        _seed_validation_inputs(srv)
        uid = str((l1.get("user_info") or {}).get("id") or fallback_uid)
        out = _unique(out_dir / ("save-%s-%s.gfsave.zip"
                                 % (uid, time.strftime("%Y%m%d"))))
        from savepack import cli
        rc = cli.main(["pack", "--from", "local",
                       "--server", str(srv), "--out", str(out)])
        if rc != 0:
            raise PackError("打包失败（退出码 %d）" % rc)
        return out
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _selftest(net: bool = False) -> int:
    """检查打包进去的数据文件是否齐全（不联网、不碰 hosts）。

    net=True 时额外起一次代理并打官方 version 接口 —— 只绑 80 端口、
    不改 hosts、不碰游戏，用来验证 exe 里的转发链能不能工作。
    """
    here = official.bundle_dir()
    print("内置数据目录：%s" % here)
    ok = True
    try:
        tpl = official.load_template()
        print("  模板        %4d 键  %s" % (len(tpl), official.template_path()))
    except PackError as exc:
        print("  模板        [失败] %s" % exc)
        ok = False
    for name in ("official_baseline.json", "official_item_ids.json"):
        p = here / name
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                n = len(obj.get("responses", {}).get(
                    "/index.php/1000/Index/index", obj))
            else:
                n = len(obj) if hasattr(obj, "__len__") else 0
            print("  %-12s %4d 项  %s" % (name, n, p))
        except (OSError, ValueError) as exc:
            print("  %-12s [失败] %s" % (name, exc))
            ok = False
    if net:
        print()
        print("网络自检（抓包部分需要管理员）：")
        ip = None
        try:
            ip = proxy.resolve_gateway()
            print("  网关 %s" % ip)
            status, raw = official._post_via_ip(
                ip, "Index/version", "=&req_id=%d001" % int(time.time()))
            print("  version -> HTTP %s，%d 字节" % (status, len(raw)))
            if status != 200:
                ok = False
        except Exception as exc:  # noqa: BLE001
            print("  [失败] %s: %s" % (type(exc).__name__, exc))
            ok = False

        # 端到端：抓自己刚发的流量，再用新解析器把它解出来。
        # 这一步过了，实机再失败就只可能是「游戏没走这个 IP」之类的外部原因。
        cap = None
        try:
            cap = capture.Capture()
            cap.start(ips=[ip] if ip else None)
            print("  抓包：%s" % cap.status_text())
            sent = 0
            if ip:
                status2, _raw2 = official._post_via_ip(
                    ip, "Index/version", "=&req_id=%d002" % int(time.time()))
                sent = 1
                print("  抓包期间再发一次 version -> HTTP %s" % status2)
            time.sleep(0.6)
            pcap = cap.stop()
            print("  pcapng %.0f KB" % (pcap.stat().st_size / 1024.0))

            scan = live.scan_capture(pcap)
            print("  %s" % scan["reader"])
            print("  %s" % scan["interfaces"])
            hits = [m for m in scan["requests"]
                    if "Index/version" in (m.target or "")]
            print("  解析器：提取到 %d 条 Index/version 请求（发了 %d 条）"
                  % (len(hits), sent))
            if sent and not hits:
                print("  [失败] 解析器没能解出自己刚发的流量")
                print(live.diagnose_text(scan))
                ok = False
        except Exception as exc:  # noqa: BLE001
            print("  [失败] 抓包解析：%s: %s" % (type(exc).__name__, exc))
            ok = False
        finally:
            if cap is not None:
                cap.cleanup()

    print()
    print("自检%s" % ("通过" if ok else "失败"))
    return 0 if ok else 1


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    print("      （同名包已存在，直接覆盖）")
    try:
        path.unlink()
    except OSError as exc:
        raise PackError("旧包删不掉：%s（%s）" % (path, exc)) from exc
    return path


def _human(n: int) -> str:
    if n >= 1048576:
        return "%.1f MB" % (n / 1048576.0)
    if n >= 1024:
        return "%.0f KB" % (n / 1024.0)
    return "%d B" % n


def _arg_value(argv, name):
    """取 `--name value` 形式的参数值。"""
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def _need_admin(no_pause: bool) -> int:
    print("[错误] 抓包需要管理员权限。")
    print("  请右键 → 「以管理员身份运行」。")
    print("  （只想离线复现的话，加 --from-pcap <文件> 不需要管理员）")
    if not no_pause:
        input("\n按回车退出…")
    return 1


def main() -> int:
    _setup_console()
    argv = list(sys.argv[1:])
    no_pause = "--no-pause" in argv
    if no_pause:
        argv.remove("--no-pause")

    if "--selftest" in argv:
        argv.remove("--selftest")
        return _selftest(net="--net" in argv)

    if "--fix-hosts" in argv:
        argv.remove("--fix-hosts")
        if not proxy.is_admin():
            if _relaunch_as_admin():
                return 0
            return _need_admin(no_pause)
        return _fix_hosts()

    from_pcap = _arg_value(argv, "--from-pcap")
    gateway = _arg_value(argv, "--gateway")
    keep = "--keep-capture" in argv
    use_filter = "--no-filter" not in argv

    if not from_pcap:
        if _relaunch_as_admin():
            return 0
        if not proxy.is_admin():
            return _need_admin(no_pause)

    try:
        rc = run(from_pcap=from_pcap, keep=keep, use_filter=use_filter,
                 gateway=gateway)
    except PackError as exc:
        print()
        print("[失败] %s" % exc)
        rc = 1
    except KeyboardInterrupt:
        print("\n已取消。")
        rc = 130
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        rc = 1

    if not no_pause:
        try:
            input("\n按回车退出…")
        except (EOFError, KeyboardInterrupt):
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
