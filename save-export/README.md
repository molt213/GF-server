# 官方账号存档导出（save-export）

把《少女前线》Steam / PC 继承版账号的**当前进度**导出成私服可导入的
`save-<uid>-<yyyymmdd>.gfsave.zip`。

纯标准库，不依赖任何第三方包。抓包用 Windows 自带的 `pktmon`。

## 它做了什么

```
pktmon 抓登录流量（只留网关 IP:80，一次登录约 18 KB）
  → pcapng 解析（字节序 / linktype / EPB / 坏块重同步）
  → TCP 4 元组重组 + HTTP/1.x 解包
  → 取 Index/getUidPC 的**响应**，解出 uid / sign（不重放请求）
  → 用 fresh sign 自己拉 Index/index（83 键），失败则退回抓包里客户端收到的那份
  → 补拉 Friend/list（好友）、Friend/dormInfo（家具）、Battlepass/index、
    Daily/index、Sangvis/duplicateIndex、Chess/index、Dorm/spare_name_list
  → 合并私服专有的 32 键（同名直搬 3 + 本地推算 5 + 结构转换 6，其余保持模板）
  → normalize（身份归一）+ validate（83 键基线）→ 打包
```

## 为什么只读响应，不重放请求

服务端按 `req_id` 去重，原样重放会被拒；而且 ticket 有时效。直接读客户端
**自己收到**的那份响应，req_id / ticket 都是当时有效的。抓包文件出包后即删，
不打印任何凭据值。

## 用法

Windows，**管理员**权限（pktmon 需要）：

```bat
GF存档导出.exe
```

流程：

1. 工具启动 pktmon 过滤器，只抓游戏网关 IP 的 80 端口。
2. 按提示启动游戏，登录到主界面。**顺手点开一次「好友」页** —— 客户端会
   拉一次 `Friend/list`，抓包里就能白拿；不点也行，工具会用会话凭据补拉一次。
3. 回到控制台按回车。
4. 产出 `save-<uid>-<yyyymmdd>.gfsave.zip`。

把这个 zip 传到手机，在「GF 私服」App 里点「导入存档」选中它，再点「启动」。

## 运行源码

```bash
cd save-export
python official_entry.py
```

需要 Python 3.9+（用到 `from __future__ import annotations`）。不需要装包。

## 排障

```bat
:: 抓包失败会留下文件并打印诊断；之后离线复现（不需要管理员、不用重登游戏）
GF存档导出.exe --from-pcap "C:\...\GF抓包-20261113-110000.pcapng"

:: 怀疑网关 IP 变了 / 抓不到包：去掉 pktmon 过滤器
GF存档导出.exe --no-filter

:: 端到端自检：发一个已知请求、同时抓包、再用解析器解出来
GF存档导出.exe --selftest --net
```

失败时会打印：字节序、接口数、各 linktype 的包数、丢弃原因、TCP 流列表
（两端 + 收发字节数）、路由命中次数。抓包会复制一份到 exe 旁边方便取出。

## 自测

```bash
cd save-export
python -m savepack.selftest
```

17 步，纯离线（合成 pcapng / 造数），覆盖：跨段 HTTP、VLAN、裸 IP、大端、
重复包、uid 红线、篡改检测、normalize、validate、好友双解、补充键白名单、
本地推算与结构转换。全过约 2 秒。

## 目录

| 文件 | 作用 |
|---|---|
| `official_entry.py` | 主流程与 exe 入口 |
| `savepack/capture.py` | pktmon 抓包 + filter 管理 + etl2pcap |
| `savepack/pcapng.py` | pcapng 读取（SHB 字节序 / IDB / EPB / SPB / 坏块重同步） |
| `savepack/tcpflow.py` | 链路层（Ethernet/VLAN/裸 IP/SLL）+ IP + TCP 重组 + HTTP 解析 |
| `savepack/live.py` | 三层提取（响应配对 → 响应盲试 → 原始字节正则）+ 好友列表 + 诊断 |
| `savepack/envelope.py` | AC.AuthCode 信封（客户端侧，MD5 是协议要求） |
| `savepack/official.py` | 拉 Index/index、补充接口、合并模板、写临时 server 目录 |
| `savepack/normalize.py` | 身份归一（以 `user_info.id` 为权威改全部行级 `user_id`） |
| `savepack/validate.py` | 83 键基线校验 |
| `savepack/packer.py` | gfsave.zip 打包 |
| `savepack/official_template.json` | 私服专有 32 键的默认值（脱敏示例档） |
| `savepack/official_baseline.json` | 官方 83 键的类型骨架 |
| `savepack/official_item_ids.json` | STC 道具 id（validate 告警用） |

## 说明

- 只读取**自己账号**的数据；好友列表只搬 `Friend/list` 本来就带的字段，
  名片 / 支援梯队不在这个响应里，留空并标 `detail_known=false`。
- `blackcard_granted` 导出时强制清零，否则导入后私服认为「已送过首登黑卡」。
- 内置模板里的 uid / 昵称是脱敏占位值，`normalize` 会按实际登录 uid 重写。
