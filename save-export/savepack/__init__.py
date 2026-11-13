"""savepack —— GF 私服 A+B 存档打包工具（纯标准库）。

包格式（唯一契约，手机端只认这 8 条数据路径 + meta.json）::

    save-<uid>-<yyyymmdd>.gfsave.zip
      meta.json                                    来源/时间/uid/每文件 sha256/计数
      content/player/l1.json                       必需
      content/player/mail.json                     可选（B 补）
      content/player/mission_reward_ledger.json    可选
      data/battle_state.json                       可选
      data/career_claim_ledger.json                可选
      data/daily_quest_state.json                  可选
      data/friend_state.json                       可选
      data/friends.json                            可选（服务端 Friend/list 原样）

账号 id 规则：以 content/player/l1.json 的 user_info.id 为准；B 拉到的 uid
与其不一致时报错（拒绝静默改写）。存档内不做 9900001 归一——服务端跟随该 id。

用法::

    python -m savepack pack --from local|snapshot|local+b --server <dir> --out <zip>
                            [--capture <pcapng>] [--snapshot <dir|json>] [--with-friends]
    python -m savepack inspect <zip> [--server <dir>]
    python -m savepack verify <zip> [--server <dir>]      # 退出码 0/1
    python -m savepack unpack <zip> --to <dir>
"""

__version__ = "1.0.0"
