# -*- coding: utf-8 -*-
"""规则管理：默认规则生成、读写、校验、增删改。"""

import copy
import json
import os
import re
import threading
import time
import uuid

from . import config
from .models import ALL_SOURCES, SEVERITY_ORDER

VALID_MATCH_MODES = ("substring", "word", "regex")
VALID_ACTIONS = ("block", "monitor")
VALID_SEVERITIES = tuple(SEVERITY_ORDER.keys())

MARKER = "AGENT_WAF_HOME"      # 保留：供 install_path 复用

# 内置规则版本号。每次往 DEFAULT_RULES 里加/改规则就 +1，
# 已有的 rules.json 会在加载时自动合并新规则（见 migrate_document）。
#
# 注意：**改了任何内置规则的内容都必须 +1**，否则磁盘上的 rules.json
# 不会更新（迁移靠 rev 比较触发）。实测踩过：改完正则忘了提版本，
# 测试跑出来的还是旧规则的行为。
DEFAULTS_REV = 16

# rev < 此值的规则视为"早期内置规则"，允许升级时刷新内容。
# 仅用于兼容没有 _builtin_hash 标记的历史文件；rev 达到此值后，
# 一律靠内容指纹判断，不会再有这个歧义。
LEGACY_REV_CUTOFF = 4

_lock = threading.RLock()


# ---------------------------------------------------------------- 跨进程写锁
#
# 为什么需要（实测复现）：
# ``_lock`` 只是**同进程内**的线程锁。而改 rules.json 的有两类进程：
#   * 控制台进程（UI / API 改规则、切开关）
#   * 独立的 wafctl（unlock / off / 规则增删）
# 两者并发「读 → 改 → 写」时，后写者拿着**自己读到的旧内容**整体覆盖，
# 前者的改动静默消失。
#
# 实测（两个子进程、中间 sleep 制造交错）：
#   A 关掉 R-101、B 暂停整体 → 最终 settings.enabled 回到 True，
#   B 明明"写入成功"了却没有任何效果。
#
# 用文件锁串行化整个「读-改-写」之外的写入段。锁粒度只到 save_document，
# 所以仍有"读之后、写之前被别人改掉"的窗口 —— 但那属于需要事务的
# 场景，本工具用「写前重读 + 只合并差异」代价太大；锁掉整段是最小
# 改动里收益最大的一档（挡住绝大多数并发写）。
#
# 平台差异：Windows 用 msvcrt.locking，POSIX 用 fcntl.flock。
# 拿不到锁时**等待重试**，超时后照常写入（fail-open）—— 规则保存
# 失败比并发覆盖更烦人；而且写入本身是原子的（tmp + os.replace）。

_WRITE_LOCK_TIMEOUT = 5.0
_WRITE_LOCK_POLL = 0.05


class _CrossProcessLock(object):
    """基于 lock 文件的跨进程互斥（带超时，拿不到就放行）。"""

    def __init__(self, target_path):
        self.path = target_path + ".lock"
        self.fh = None

    def __enter__(self):
        try:
            self.fh = open(self.path, "a+")
        except OSError:
            self.fh = None
            return self
        deadline = time.time() + _WRITE_LOCK_TIMEOUT
        while True:
            try:
                self._acquire()
                return self
            except Exception:
                if time.time() >= deadline:
                    return self          # 超时 → 放行（fail-open）
                time.sleep(_WRITE_LOCK_POLL)

    def _acquire(self):
        if os.name == "nt":
            import msvcrt
            self.fh.seek(0)
            msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def __exit__(self, *exc):
        try:
            if self.fh is None:
                return False
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        finally:
            try:
                if self.fh is not None:
                    self.fh.close()
            except Exception:
                pass
        return False


DEFAULT_SETTINGS = {
    "enabled": True,
    "mode": "block",
    "case_sensitive": False,
    "normalize": ["url_decode", "html_unescape", "unicode_unescape",
                  "fold_fullwidth", "strip_invisible", "collapse_ws",
                  "compact", "lower"],
    "scan_headers": True,
    "max_scan_bytes": 262144,
    "fail_mode": "closed",
    "log_allowed": False,
    "unlock_until": 0,
    "unlock_reason": "",
}


# ---------------------------------------------------------------- 默认规则

DEFAULT_RULES = [
    {
        "id": "R-101",
        "name": "删除 / 销毁类操作（不可逆）",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            # ----------------------------------------------------------
            # 这里的关键词不再一股脑用 substring 匹配。
            #
            # 为什么：实测 10 个正常 Web 请求全被误拦 ——
            #   removeFromCart=1    购物车（camelCase 标识符）
            #   remove_tag=php      API 参数名
            #   purge_cache=false   配置开关
            #   ?q=how+to+remove    搜索词
            #   body: To remove an item   页面文案
            # remove / purge / erase 这些词在真实业务里出现频率极高，
            # 全拦的后果是用户被烦到直接 wafctl off —— 防护归零，
            # 比不拦更糟。
            #
            # 判据改成"**动作位置**"：删除词必须出现在
            #   开头 / = : / . ( [ 空格 之后，且后面不是字母数字下划线
            # 这样 action=remove、/cart/remove、api.remove( 都命中，
            # 而 removeFromCart、remove_tag、how to remove 不再误伤。
            #
            # 复合词（removeitem / deletefile…）本身就有辨识度，
            # 仍然用 substring 直接匹配。
            # ----------------------------------------------------------
            "removeall", "remove_all", "removedir", "removefile",
            "removedirectory", "removeitem", "remove-files", "deletefile",
            "delete_file", "deletemany", "bulk_delete", "bulkdelete",
            # purge/erase/wipe 的复合形式。这些带后缀的写法辨识度高
            # （不会和业务词撞车），可以放心用 substring。
            # 注意必须同时列下划线和压缩两种形态：归一化的 compact 变体
            # 会把 purge_all 变成 purgeall（实测漏过这一个）。
            "purge_all", "purgeall", "purge-all", "purgeallusers",
            "erase_all", "eraseall", "erase-all",
            "wipe_all", "wipeall", "wipe-all", "wipedata", "wipe_data",
            "flushall", "flush_all", "truncate_all", "truncateall",
            # 销毁 / 抹除词族（生僻词，substring 即可）
            "obliterate", "annihilate", "exterminate",
            # 粉碎 / 清空词族里的生僻词
            "shred", "unlink", "nuke", "scour",
            # 文件系统删除命令
            "rmdir", "rimraf", "deltree", "delfile", "del /f", "del /q",
            "rm -rf", "rm -fr", "rm -r", "rmrf",
            # SQL 破坏语句
            "drop table", "drop database", "drop schema", "drop index",
            "drop view", "delete from", "truncate table", "remove from",
            # 账户删除
            "userdel", "groupdel",
            # 强删 / 覆盖语义标记
            "force-delete", "force_delete", "hard_delete", "hard-delete",
            "hard delete", "permanent_delete", "permanentdelete",
            # 进程 / 服务销毁
            "kill -9", "pkill", "killall", "taskkill",
        ],
        "regex": [
            # ---- 高频词限定在"动作位置" ----
            # 分隔符集合含下划线/连字符：item_delete、batch_delete、
            # user-remove 这类命名都算"动作位置"（下划线是词字符，
            # \b 在这里不管用 —— 实测漏过 item_delete 一族）。
            r"(?:^|[=\s:/.\{\[\(,;'\"_\-])(?:remove|purge|erase|destroy|wipe|"
            r"destruct|shred|nuke|unlink)(?![a-zA-Z0-9_])",
            r"\brm\s+-[a-zA-Z]*[rf]",
            r"\bdel\b\s+/[a-z]",
            r"\bformat\s+[a-z]:",
            r"\bdrop\s+(table|database|schema|index|view)\b",
            r"\btruncate\s+table\b",
            r"\bdelete\s+from\b",
            # delete 在业务里比 remove 少见，直接拦；但**不能只拦"裸词"** ——
            # 主战场恰恰是 deleteById / deleteRecord / deleteUser 这类接口名。
            #
            # 判据演进（三次踩坑，每次都留下一类漏拦）：
            #   1. \bdelete(?![a-zA-Z0-9_]*(?:d|_at|_flag))
            #      断言里的 d 是"任意位置的 d"，[a-zA-Z0-9_]* 可回溯 ——
            #      deleteRecord 里 Recor**d** 就触发豁免。
            #   2. \bdelete(?!d)
            #      只排除"紧跟 d"，但 re.I 下 deleteDomain / deleteDraft /
            #      deleteData / deleteDevice / deleteDoc / deleteDepartment
            #      的 D 也被排除（实测 6 条全漏）。
            #   3. 现在：分隔符（含 _ -）+ delete + 其后不是
            #      "d+非字母"（deleted 过去式）或 "dAt"（camelCase 状态字段）。
            #      实测 20/20：deleteXxx 全拦，deleted/deleted_at/deletedAt 放行。
            #
            # 注意用动作位形式而不是 \b：下划线是词字符，\b 在
            # item_delete 里不成立（与上面 remove 一族同样的原因）。
            r"(?:^|[=\s:/.\{\[\(,;'\"_\-])delete(?!d(?![a-zA-Z])|dAt\b)",
            # 分隔符拆字绕过：d_e_l_e_t_e / d.e.l.e.t.e / d e l e t e。
            # 归一化里的 compact 会把它压回 delete，但那时 offset 已经
            # 失去原文坐标（压缩后 qdelete 与 removefromcart 无法区分），
            # 所以必须在**原文**上识别。允许字母间插入最多 2 个分隔符，
            # 且要求整体是独立词（后面的 (?![a-z0-9_]) 保证不误伤
            # deleted_at / deletefrom 这类标识符）。
            r"d[_\-.\s]{0,2}e[_\-.\s]{0,2}l[_\-.\s]{0,2}e"
            r"[_\-.\s]{0,2}t[_\-.\s]{0,2}e(?![a-zA-Z0-9_])",
            r"r[_\-.\s]{0,2}e[_\-.\s]{0,2}m[_\-.\s]{0,2}o"
            r"[_\-.\s]{0,2}v[_\-.\s]{0,2}e(?![a-zA-Z0-9_])",
            r"\bgit\s+rm\b",
            r"\bsvn\s+(delete|del|remove|rm)\b",
            r"\b(remove|delete|unlink)(file|dir|directory|item)\s*\(",
        ],
        "exclude": [
            # 软删除字段名（业务标识符，不是动作）
            "deleted_at", "is_deleted", "soft_delete", "delete_flag",
            "undelete", "no_delete", "not_delete", "can_delete",
            "allow_delete", "deleteable", "deletable", "delete_on",
            "deletion_policy", "delete_after", "non_deletable",
            # 搜索/查询参数里的删除词 = 用户在搜这个词，不是要执行它。
            # 实测 `?q=how+to+remove+a+virus` 这类会被误拦。
            #
            # 但**不能无脑放过 q=**：`?q=delete+from+users`、
            # `?q=d_e_l_e_t_e` 正是注入/绕过载荷，实测一放开就漏拦。
            # 所以再加两个限制：
            #   * 值里不能出现 SQL/命令语法（from/table/where/--/;/$
            #     等）—— 出现说明是载荷而非自然语言
            #   * 删除词两侧都要有词（自然语言的句子形态），
            #     像 d_e_l_e_t_e 这种被分隔符拆开的要照样拦
            r"(?:^|[?&])(?:q|query|search|keyword|kw|k|s|text|term|title|"
            r"desc|content|comment|message|note|body|filter|sort)"
            r"=(?![^&]*\b(?:from|table|where|select|insert|update|union|"
            r"drop|into|outfile|information_schema|xp_|--|;|\$\())"
            r"[^&]*?[\s+](?:remove|delete|purge|erase)\b",
            # 同上的"删除词在**前**"版本：`?message=delete the old records
            # please`。
            #
            # 为什么需要重写（实测，5/5 绕过）：原先这里是一条
            # **未锚定参数名**的宽泛规则
            #     (?:^|[=\s:])词(?:[\s+]词){2,}[\s+]delete
            # 本意是放过 "how to delete my account" 这类搜索描述，但
            # 不限定参数名 → 任意**动作参数**都能用 词+词+词+delete
            # 触发豁免：
            #     op=a+b+c+delete            ← 9 字符就让 R-101 失效
            #     action=just do it delete now&id=1
            # 这是核心规则失守，不是误报治理问题。
            #
            # 现在锚定到同一批搜索参数（与上面那条同构），并保留
            # SQL 守卫：`?q=delete from users` 这类载荷照样拦。
            r"(?:^|[?&])(?:q|query|search|keyword|kw|k|s|text|term|title|"
            r"desc|content|comment|message|note|body|filter|sort)"
            r"=(?![^&]*\b(?:from|table|where|select|insert|update|union|"
            r"drop|into|outfile|information_schema|xp_|--|;|\$\())"
            r"[^&]*?\b(?:remove|delete|purge|erase)[\s+]"
            r"(?:[\w,.;:!?'\"()-]+[\s+]){1,}",
        ],
        "note": "防止 AI 或手滑触发删除/销毁，删除类动作一律先请示",
    },
    {
        "id": "R-105",
        "name": "短删除指令 del / rm（词边界精确匹配）",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "word",
        "keywords": ["del", "rm", "rmdir", "dels", "delall", "rmall"],
        "regex": [],
        # 不需要 exclude：词边界已经保证 model / delay / order / handler
        # / confirm / format 这些正常单词不会命中（"del"、"rm" 在其中
        # 不是独立词）。反过来，若用 exclude，"/del/order" 这种真实
        # 删除端点反而会被误抑制。
        "exclude": [],
        "note": "del / rm 是核心删除命令与常见 URL 路径段（/del/a.txt、?op=del）",
    },
    {
        "id": "R-106",
        "name": "删除命令的 Windows / SCM / 脚本写法",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "regex",
        "keywords": [],
        "regex": [
            r"(?<![a-z0-9_])rd\s+/[sq]",
            r"(?<![a-z0-9_])del\s+\"?[a-z]:\\",
            r"(?<![a-z0-9_])erase\s+/[a-z]",
            r"(?<![a-z0-9_])rm\s+-[a-z]*\s+/",
            r"(?<![a-z0-9_])rm[_-][a-z]",
            r"(?<![a-z0-9_])del[_-][a-z]",
            r"\bRemove-Item\b",
            r"\bRemove-ItemProperty\b",
            r"\bDeleteFile\b",
            r"\bRemoveDirectory\b",
            r"\bSHFileOperation\b",
            r"\bIFileOperation\b",
            r"\bos\.remove\b",
            r"\bos\.unlink\b",
            r"\bshutil\.rmtree\b",
            r"\brimraf\b",
            r"\bfs\.unlink\b",
            r"\bfs\.rm\b",
            r"\bfs\.rmdir\b",
            r"\bsubprocess\.(run|call|Popen)\b.*\b(rm|del|erase|rmdir)\b",
            r"\bunlink\s*\(",
            r"\bdeleteOne\b",
            r"\bdeleteMany\b",
            r"\bfindOneAndDelete\b",
            r"\bfindByIdAndDelete\b",
            r"\bremoveOne\b",
            r"\bremoveMany\b",
            r"\bdestroy\s*\(",
        ],
        "exclude": [],
        "note": "rd /s、del C:\\、Remove-Item、os.remove、rmtree 等命令式删除写法",
    },
    {
        "id": "R-102",
        "name": "数据库破坏类语句",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "regex",
        "keywords": [],
        "regex": [
            r"\bdrop\s+(table|database|schema|index|view)\b",
            r"\btruncate\s+table\b",
            # TRUNCATE 后面**直接跟标识符**（MySQL/PG 的合法写法：
            # TRUNCATE users;）—— 实测只查 "truncate table" 时
            # `TRUNCATE users` 直接过。
            #
            # 误伤控制靠一张"自然语言停用词"表：TRUNCATE 后面跟
            # the/file/string/data 这类词的，是在说"截断字符串/文件"，
            # 不是 SQL。判据只排除**紧跟其后**的那个词，所以
            # `truncate the users table` 也不拦（那本来就不是 SQL）。
            # 注意复数形式要逐个列出：lookahead 里的 \b 不会让
            # "file" 命中 "files"。
            r"\btruncate\s+(?:table\s+)?(?:if\s+exists\s+)?[\`\"\[]?"
            r"(?!(?:the|this|that|these|those|a|an|all|any|its|it|my|our|"
            r"your|their|to|and|or|for|with|from)\b)"
            r"(?!(?:string|strings|text|line|lines|file|files|log|logs|"
            r"data|value|values|name|names|column|columns|field|fields|"
            r"input|output|length|size|count|message|messages|path|url|"
            r"content|result|results|buffer|array|arraylist|list|number|"
            r"numbers|time|date|table|tables|row|rows|space|whitespace)\b)"
            r"[a-z_][a-z0-9_$]*[\`\"\]]?",
            # Redis 清库。FLUSHALL 在 R-101 关键词里，FLUSHDB 实测
            # 两条规则都拦不到（用户报告的绕过之一）。
            r"\bflushdb\b",
            r"\bflushall\b",
            # Mongo / ORM 的**驼峰与下划线写法**：db.dropDatabase()、
            # drop_collection、deleteCollection、removeDB……
            # `drop\s+database` 那种写法一个都匹配不到。
            r"\b(?:drop|delete|remove)[\s_\-]?(?:database|db|collection|"
            r"collections)s?\b",
            # pymongo / mongosh：collection.drop()
            r"\.drop\s*\(\s*\)",
            r"\bdelete\s+from\b",
            r"\bupdate\s+\w+\s+set\b.*\bwhere\s+1\s*=\s*1",
            r"\bshutdown\b",
        ],
        "exclude": [],
        "note": "SQL 层面不可逆操作",
    },
    {
        "id": "R-103",
        "name": "本地文件系统破坏",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "regex",
        "keywords": [">/dev/sda", "mkfs", "dd if=", ":(){:|:&};:"],
        "regex": [
            r"\bmkfs(\.\w+)?\b",
            r"\bdd\s+if=.*of=/dev/",
            r">\s*/dev/sd[a-z]",
            r"\bchmod\s+-R\s+777\s+/\s*$",
            r"\b:\(\)\s*\{.*\};:",
        ],
        "exclude": [],
        "note": "直接破坏磁盘 / fork 炸弹",
    },
    {
        "id": "R-104",
        "name": "权限与账户破坏",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "regex",
        "keywords": ["userdel", "groupdel", "passwd -d", "net user /delete"],
        "regex": [
            r"\buserdel\b",
            r"\bgroupdel\b",
            r"\bnet\s+user\b.*\/delete\b",
            r"\bDROP\s+USER\b",
        ],
        "exclude": [],
        "note": "删除账户 / 组成员",
    },
    {
        "id": "R-107",
        "name": "权限变更 / 表结构破坏",
        "enabled": True,
        "severity": "high",
        "action": "block",
        # grant / revoke 用 word 模式而不是 substring：
        # OAuth 的 grant_type 是**最高频的正常参数之一**，
        # substring 会把它一起拦下（实测 "grant " 这个带空格的写法
        # 恰好躲过了 grant_type，但 body 里的 "grant": 形态躲不过）。
        # word 模式的边界是 [a-z0-9_]：grant_type / granted / revokeAll
        # 全都不命中，GRANT ALL ON *.* TO ... 照拦。
        "match_mode": "regex",
        "keywords": [],
        "regex": [
            # GRANT/REVOKE 的**语句形态**，而不是把 "grant" 当裸词拦。
            #
            # 为什么不能用裸词（实测）：OAuth 的 grant_type 是最高频的
            # 正常参数之一，而 IAM 类接口里 "grant" 本身就是一个权限
            # 动作名（{"permission":"grant"}、scope 串里的 grant:write）。
            # 裸词（哪怕带词边界）会把这些正常请求一起拦下。
            # 这里要求 grant/revoke 后面**跟一个真实的权限词**，
            # 或者构成 "GRANT <角色> TO <主体>" 的完整句式。
            r"\b(?:grant|revoke)\s+(?:all|select|insert|update|delete|"
            r"drop|alter|create|execute|usage|references|truncate|super|"
            r"connect|temporary|replication|privileges|role)\b",
            r"\bgrant\s+\w{1,40}\s+to\s+\w",
            r"\brevoke\s+\w{1,40}\s+from\s+\w",
            # 表结构破坏
            r"\balter\s+table\b[^;]{0,240}?\bdrop\b",
            r"\bdrop\s+(?:column|constraint|partition|trigger)\b",
            # 账户提权（不改密码不算，改了就是接管）
            r"\balter\s+(?:user|role)\b[^;]{0,200}?\b(?:identified|password|"
            r"superuser|createdb|createrole)\b",
        ],
        "exclude": [],
        "note": "GRANT/REVOKE 提权与 ALTER TABLE ... DROP 结构破坏；"
                "原先只记在 R-201（monitor），按实测建议提到 block",
    },
    {
        "id": "R-201",
        "name": "危险写操作（需人工确认）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "substring",
        "keywords": [
            # grant / revoke 已提到 R-107 按 block 处理，这里不再重复
            # 记录（同一个词命中两条规则只会在事件里多一条噪声）。
            # alter table 保留：非破坏性的 ALTER 仍值得留痕，
            # 破坏性的 ALTER TABLE ... DROP 由 R-107 拦下。
            "update ", "insert into", "alter table",
            "chmod ", "chown ", "overwrite", "> /etc/", "shutdown -h",
            "reboot", "halt",
        ],
        "regex": [],
        "exclude": [],
        "note": "默认只记录不拦截；确认无风险后可改为 block",
    },
    {
        "id": "R-202",
        "name": "高影响漏洞利用动作（自测留痕）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "substring",
        "keywords": [
            "/etc/passwd", "cmd.exe", "/bin/sh", "/bin/bash",
            "union select", "sleep(", "waitfor delay", "xp_cmdshell",
            "java.lang.runtime", "${jndi:", "../..", "php://input",
            "base64_decode(", "system(", "shell_exec",
        ],
        "regex": [],
        "exclude": [],
        "note": "漏洞验证常见 payload：只记录，便于回溯自己做过什么",
    },
    {
        "id": "R-203",
        "name": "反弹 Shell / 数据外带",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "regex",
        "keywords": ["/dev/tcp/", "nc -e", "ncat -e", "bash -i", "meterpreter"],
        "regex": [
            r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+",
            r"\b(nc|ncat|netcat)\b.*\s-[a-zA-Z]*e\b",
            r"\bbash\s+-[ic]\b.*>&\s*/dev/tcp",
            r"\bmkfifo\b.*\|\s*(nc|ncat|bash)",
        ],
        "exclude": [],
        "note": "反弹 shell 类动作极易失控，默认拦截",
    },
    # ----------------------------------------------------------------
    # R-3xx：与"删除"同级的不可逆 / 高法律风险操作
    #
    # 分组即独立规则，UI 里可单独开关。判定原则：
    #   * 只拦"不可逆"或"法律风险高"的动作；正常渗透手段一律放行
    #   * 读取类动作（读日志、列权限、看历史）不拦 —— 那是干活必需
    #   * 工具名不整体拦（如 sqlmap），只在带破坏性参数时拦
    # ----------------------------------------------------------------
    {
        "id": "R-301",
        "name": "脱库 / 数据外带（批量导出）",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "into outfile", "into dumpfile", "--dump-all", "--all-databases",
        ],
        "regex": [
            # 判定"真的在跑导出工具"，需要满足两条之一：
            #   a) 后面跟 flag：mysqldump -u root db、pg_dump --all-databases
            #   b) 后面跟重定向或管道：mysqldump db > a.sql、pg_dump db | nc ip
            # 只写工具名（?page=mysqldump-guide）或"工具名 + 单词"
            # （?q=pg_dump usage，搜索词）都不算 —— 那样会把查文档误拦。
            # 实测踩过两次：先用 \s+--?\w 漏了位置参数形式，改用 \s+\S 又
            # 把搜索词拦了；最终就用这两条精确判据。
            # pg_dump 分支必须写 (?:all)? —— 写成 all? 会变成 "al + 可选 l"。
            r"\b(?:mysqldump|pg_dump(?:all)?|mongodump)\b\s+-{1,2}\w",
            r"\b(?:mysqldump|pg_dump(?:all)?|mongodump)\b[^\n]{0,100}?[>|]",
            r"into\s*(?:/\*[^*]*\*/)?\s*(outfile|dumpfile)",
            r"\bsqlmap\b[^\n]*--(dump|dump-all|os-shell|sql-shell|file-read|file-write)",
            r"\bload_file\s*\(",
        ],
        "exclude": [],
        "note": "批量导出数据 = 脱库；法律风险高于技术风险。确需验证先 wafctl unlock",
    },
    {
        "id": "R-302",
        "name": "后门 / 持久化",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "authorized_keys", "crontab -e", "/etc/cron.d",
            "schtasks /create", "sc create", "register-scheduledtask",
            "new-service", "useradd", "adduser",
        ],
        "regex": [
            r"eval\s*\(\s*\$_(POST|GET|REQUEST)",
            r"\b(assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_",
            r">>\s*\S*\.ssh/authorized_keys",
            r"\bcrontab\s+-[er]\b",
            r"/etc/(cron\.(d|daily|hourly)|systemd/system)/",
            r"\breg\s+add\b[^\n]*\\Run\b",
            r">>\s*(?:~|\$HOME)?/?\.(?:bashrc|bash_profile|profile|zshrc)\b",
            # 必须带 /add 才算建账号：`net user`（列用户）、
            # `net localgroup administrators`（看组）都是常规信息收集，
            # 不能拦（测试抓过这个误报）
            r"\bnet\s+(?:user|localgroup)\b[^\n]*?\s\/add\b",
        ],
        "exclude": [],
        "note": "留后门 / 建持久化，授权范围外极易被认定为主观恶意",
    },
    {
        "id": "R-303",
        "name": "痕迹清理 / 日志清除",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "history -c", "unset histfile", "wevtutil cl", "clear-eventlog",
            "auditctl -e 0", "setenforce 0",
        ],
        "regex": [
            # 必须"删除动词 + 日志目标"同现：单纯读日志（LFI 读 access.log）
            # 是正常渗透步骤，不能拦
            r"\b(rm|shred|truncate|unlink)\b[^\n]{0,80}(/var/log|\.bash_history|/wtmp|/btmp|lastlog)",
            r">\s*/var/log/",
            r"\bauditctl\s+-e\s+0\b",
            r"\bsystemctl\s+(stop|disable|mask)\s+auditd\b",
        ],
        "exclude": [],
        "note": "清理痕迹是法律风险最高的动作，正常测试绝不需要",
    },
    {
        "id": "R-304",
        "name": "云 / 容器 / IaC 资源删除",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "kubectl delete", "helm uninstall", "helm delete",
            "terraform destroy", "docker system prune", "docker volume rm",
            "docker-compose down -v", "aws s3 rb", "aws s3 rm",
            "aws ec2 terminate-instances",
        ],
        "regex": [
            r"\b(aws|az|gcloud)\b[^\n]*\b(delete|terminate|destroy|remove)\b",
            r"\bkubectl\s+delete\b",
            r"\bhelm\s+(uninstall|delete)\b",
            r"\bterraform\s+(destroy|apply\s+-destroy)\b",
            r"\bdocker\s+(rm\s+-f|rmi|system\s+prune|volume\s+rm|network\s+rm)\b",
            r"\bdocker-compose\s+down\s+-v\b",
            r"\b(aws|gcloud)\b[^\n]*delete-(table|database|instance|bucket|snapshot|backup)",
        ],
        "exclude": [],
        "note": "云资源删除会同时造成账单与数据损失，多数不可逆",
    },
    {
        "id": "R-305",
        "name": "备份 / 快照删除",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "vssadmin delete shadows", "wbadmin delete", "delete-snapshot",
            "zfs destroy", "lvremove", "vgremove", "pvremove",
        ],
        "regex": [
            r"\bvssadmin\s+delete\s+shadows\b",
            r"\bwbadmin\s+delete\b",
            r"\b(aws|az|gcloud)\b[^\n]*delete-(snapshot|backup)",
            r"\b(zfs|btrfs)\b[^\n]*\b(destroy|subvolume\s+delete)\b",
            r"\b(lvremove|vgremove|pvremove)\b",
            r"\brm\b[^\n]{0,60}(/backup|/var/backups|\.snapshot)",
        ],
        "exclude": [],
        "note": "备份没了就彻底没救 —— 比删数据本身更不可逆",
    },
    {
        "id": "R-306",
        "name": "权限 / 账号体系破坏",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "substring",
        "keywords": ["visudo", "usermod -ag"],
        "regex": [
            # 只有"写" sudoers/passwd/shadow 才拦：`cat /etc/sudoers` 是
            # 常规提权检查，`cp /etc/sudoers /tmp/` 是拷出来审计 —— 读和
            # 导出都不该拦。这里逐种"写"的形态硬编码：
            #   >> /etc/sudoers        shell 重定向
            #   tee -a /etc/sudoers    管道写
            #   sed -i s/x/y/ /etc/... 原地编辑（-i 本身就是破坏性标志）
            #   cp /tmp/x /etc/passwd  覆盖目标（要求目标在**后面**，
            #                          所以"拷出去"不会被误拦）
            # 每个分支都用 [^\n]* 允许中间夹参数：
            #   sed -i 's/^/#/' /etc/sudoers —— 脚本参数在路径之前（踩过）
            r"(?:>>?\s*|tee\b[^\n]*|sed\s+-i[^\n]*|cp\s+[^\n]*\s|mv\s+[^\n]*\s"
            r"|install\s+[^\n]*\s)"
            r"(?:/etc/sudoers|\S*sudoers\.d\S*|/etc/passwd|/etc/shadow)",
            r"\b(chmod|chown)\s+-R\s+\S+\s+/(usr|etc|var|bin|sbin)\b",
            r"\busermod\s+-aG\s+(sudo|wheel|admin)\b",
            # 同上：只有 /add 才算把账号塞进管理员组
            r"\bnet\s+localgroup\s+administrators\b[^\n]*?\s\/add\b",
            # 只有改权限时才拦：单纯 icacls 列权限是常规操作
            r"\bicacls\b[^\n]*/[Gg]rant\b",
            r"\bsetfacl\b[^\n]*-R\b",
        ],
        "exclude": [],
        "note": "改 sudoers / 加管理员 = 提权后留下的高危痕迹",
    },
    {
        "id": "R-307",
        "name": "防火墙 / 安全组件关闭",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "substring",
        "keywords": ["ufw disable"],
        "regex": [
            r"\biptables\s+(?:-F|-X|--flush)\b",
            r"\biptables\s+-P\s+\w+\s+(?:ACCEPT|DROP)\b",
            r"\bufw\s+disable\b",
            r"\bfirewall-cmd\b[^\n]*--set-default-zone=trusted",
            r"\bnetsh\s+advfirewall\s+set\b[^\n]*\bstate\s+off\b",
            r"\bSet-MpPreference\b[^\n]*-Disable",
            r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|sshd|auditd|apparmor|clamd)\b",
        ],
        "exclude": [],
        "note": "关安全组件可能把你自己锁在门外，也容易触发告警",
    },
    {
        "id": "R-308",
        "name": "服务中断 / 资源耗尽",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "substring",
        "keywords": ["/dev/zero", "/dev/urandom", "hping3", "slowloris",
                     "goldeneye", "--flood"],
        "regex": [
            r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=",
            r"\bcat\s+/dev/(?:zero|urandom)\b[^\n]*>",
            r"\b(?:kill|pkill|killall)\s+-9\s+(?:-1|1)\b",
            r"\b(?:systemctl|service)\s+(?:stop|disable)\s+(?:mysqld|mariadb|postgresql|nginx|httpd|docker)\b",
            r"\b(?:hping3|slowloris|goldeneye)\b[^\n]*(?:--flood|--rand-source)",
            r"\bab\b[^\n]*-n\s+\d{5,}",
            r"\bfallocate\b[^\n]*-l\s+\d+\s*[GMT]",
        ],
        "exclude": [],
        "note": "停关键服务 / 打满资源，可能直接造成业务中断",
    },
    {
        "id": "R-309",
        "name": "凭证转储（仅记录）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "substring",
        "keywords": ["mimikatz", "sekurlsa", "secretsdump", "dcsync",
                     "kerberoast", "ntds.dit", "lsass"],
        "regex": [
            r"\bprocdump\b[^\n]*lsass",
            r"\bcomsvcs\.dll\b[^\n]*[Mm]ini[dD]ump",
            r"\breg\s+save\b[^\n]*HKLM\\(?:SAM|SYSTEM|SECURITY)",
        ],
        "exclude": [],
        "note": "授权渗透里属正常取证；若测生产域环境建议改为 block",
    },
    {
        "id": "R-310",
        "name": "Git 历史破坏",
        "enabled": True,
        "severity": "high",
        "action": "block",
        "match_mode": "substring",
        "keywords": [
            "git push --force", "git push -f", "git reset --hard",
            "git clean -fdx", "git filter-branch", "git filter-repo",
            "npm unpublish",
        ],
        "regex": [
            r"\bgit\s+push\b[^\n]*(?:--force\b|(?<!\w)-f\b)",
            r"\bgit\s+push\b[^\n]*--delete\b",
            r"\bgit\s+reset\s+--hard\b",
            r"\bgit\s+clean\s+-[fdx]+",
            r"\bgit\s+(?:filter-branch|filter-repo)\b",
            r"\bgit\s+reflog\s+(?:expire|delete)\b",
            r"\bgit\s+gc\b[^\n]*--prune=now",
            r"\bgit\s+stash\s+(?:clear|drop)\b",
        ],
        "exclude": [],
        "note": "强推 / reset --hard 会丢代码；对你自己的项目同样是不可逆损失",
    },
    {
        "id": "R-311",
        "name": "扫描器 / 爆破工具（仅记录）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "substring",
        "keywords": [
            "sqlmap", "msfconsole", "metasploit", "msfvenom", "hydra",
            "medusa", "ncrack", "patator", "ffuf", "dirsearch", "gobuster",
            "feroxbuster", "wfuzz", "dirb", "nmap", "masscan", "nuclei",
        ],
        "exclude": [],
        "note": "日常工具不拦，只留痕方便复盘 AI 到底跑过什么",
    },
    {
        "id": "R-312",
        "name": "OOB 外带通道（仅记录）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "substring",
        "keywords": [
            "dnslog", "ceye.io", "burpcollaborator", "oastify",
            "interact.sh", "oast.", "requestbin", "webhook.site",
            "pipedream", "requestrepo", "ngrok",
        ],
        "exclude": [],
        "note": "证明盲注 / SSRF 必须用外带，拦了没法干活；只记录便于核对目标",
    },
    {
        "id": "R-313",
        "name": "批量读取用户 / 订单类表（仅记录）",
        "enabled": True,
        "severity": "medium",
        "action": "monitor",
        "match_mode": "regex",
        "keywords": [],
        "regex": [
            r"\bselect\b[^\n]{0,120}\bfrom\b[^\n]{0,60}\b(?:users|accounts|members|user_info|orders|customers)\b",
        ],
        "exclude": [],
        "note": "偏宽所以只记录；确认在打生产库时再改成 block",
    },
    {
        "id": "R-314",
        "name": "密码重置 / 账号接管（不可逆）",
        "enabled": True,
        "severity": "critical",
        "action": "block",
        "match_mode": "regex",
        "keywords": [],
        "regex": [
            # 核心设计：必须「改密动作」+「密码目标」同时出现才算命中。
            # 只写 password=xxx 不拦 —— 那是登录尝试、注册、SQL 注入的
            # 常规载荷（`or 1=1` 那套），拦了就没法干活了（实测过：
            # 单纯 password 参数每天出现几十次）。
            #
            # 目标词：password / passwd / pwd / pass / 密码 / 口令
            # 动作词：reset / change / modify / set / update / force /
            #         new / 重置 / 修改 / 改成
            r"\b(?:reset|change|modify|update|set|force|new|overwrite)"
            r"[-_ ]?(?:user[-_ ]?)?(?:password|passwd|pwd)\b",
            # set_new_password / set-new-pwd 这类"动作_修饰_目标"三段式
            r"\b(?:reset|change|modify|update|set|force|overwrite)"
            r"[-_ ](?:new|old|user|admin|account|login)[-_ ]"
            r"(?:password|passwd|pwd)\b",
            r"\b(?:password|passwd|pwd)[-_ ]?"
            r"(?:reset|change|modified|updated|overwrite)\b",
            r"\bpassword\s*(?:reset|change)\b",
            # 链接式 / 接口式：  /reset-password?user=x
            #                    /password/reset
            #                    /api/user/changePassword
            r"/[a-z_-]*?(?:reset|change|modify|update)[a-z_-]*?"
            r"(?:password|passwd|pwd)\b",
            r"/(?:password|passwd|pwd)[a-z_-]*?"
            r"(?:reset|change|modify|update)\b",
            # 参数式：action=resetpass / op=changepwd / do=setpassword
            r"\b(?:action|op|do|cmd|method|func|operation)\s*=\s*"
            r"(?:reset|change|modify|set|update|force)?"
            r"(?:pass(?:word|wd)?|pwd)\b",
            # Linux 层面：直接改系统账号密码
            r"\b(?:chpasswd|passwd)\s+(?:-d\s+)?(?:root|admin|administrator)\b",
            r"\becho\s+[^\n|]{0,40}\|\s*(?:chpasswd|passwd\s+--stdin)\b",
            # Windows：net user <name> <newpass>  /  net user x /passwordchg
            r"\bnet\s+user\s+\S+\s+(?:/[a-z]+:)?\S+\s*$",
            r"\bnet\s+user\s+\S+\s+/passwordchg\b",
            # SQL 层：ALTER USER ... IDENTIFIED BY / UPDATE ... SET password
            r"\balter\s+user\b[^\n]{0,40}\bidentified\s+by\b",
            r"\bupdate\s+\S*(?:user|account|member)\S*\s+set\b[^\n]{0,60}"
            r"\b(?:pass(?:word|wd)?|pwd)\b",
            r"\bset\s+password\s*=\s*password\s*\(",
            # 中文接口名
            r"/(?:重置密码|修改密码|密码重置|找回密码|改密)\b",
        ],
        "exclude": [
            # 排除"查询/展示"语境：这些是正常功能，不是改密
            r"(?:forgot|retrieve|query|check|verify|validate|display|show|"
            r"confirm|strength|policy|history|expire|expiry|reset[-_]?token|"
            r"reset[-_]?link|send[-_]?reset|request[-_]?reset)",
            # 查询串里的字段名（软删除风格）
            r"(?:password_reset|reset_password)_(?:token|at|time|expire)",
        ],
        "note": ("改密码后原凭据永久失效，属于不可逆操作。只在"
                 "「改密动作 + 密码目标」同时出现时命中；单纯的 "
                 "password= 参数（登录/注册/SQL 注入）不拦。"),
    },
]


DEFAULT_ALLOWLIST = [
    {
        # 默认关闭：本机靶场上的 delete 测试也应该被拦（见截图场景）。
        # 需要放开时在控制台里启用它即可。
        "id": "A-001",
        "enabled": False,
        "source": "url",
        "pattern": r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/|$)",
        "note": "本机靶场放行（默认关闭；启用后 127.0.0.1 上的 delete 将不再被拦）",
    },
    {
        "id": "A-002",
        "enabled": True,
        "source": "any",
        "pattern": r"deleted_at|is_deleted|soft_delete|delete_flag",
        "note": "常见软删除字段名，避免误报",
    },
]


def default_document():
    """全新安装的初始文档。内置规则带上内容指纹，
    这样日后升级能判断"用户有没有改过这条"，与迁移过的老文件行为一致。"""
    return {
        "version": 1,
        "defaults_rev": DEFAULTS_REV,
        "removed_defaults": [],
        "settings": copy.deepcopy(DEFAULT_SETTINGS),
        "allowlist": copy.deepcopy(DEFAULT_ALLOWLIST),
        "rules": [_stamp_builtin(r) for r in DEFAULT_RULES],
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _normalize_sources(value):
    """空列表与"显式列出全部字段"语义相同。

    规则文件的写法演进过：早期把 8 个字段全列出来，现在留空表示全部。
    比较指纹时必须归一化，否则同一份规则会被误判成"用户改过"。
    """
    items = list(value or [])
    if not items or len(items) >= len(ALL_SOURCES):
        return "ALL"
    return sorted(set(items))


def _content_fingerprint(rule):
    """规则内容指纹：只含用户会编辑的字段，不含开关状态与内部标记。

    用来回答一个关键问题："这条规则现在是内容 X，用户有没有在 X 之后
    自己改过它？" 我们从不高估用户的编辑意图，但也绝不用新版覆盖
    用户的手工调整。
    """
    return _fingerprint(rule, normalize_sources=True)


def _fingerprint_legacy(rule):
    """旧版指纹算法（sources 未归一化）。

    指纹算法本身升级过：磁盘上已存的老哈希是用旧算法算的。
    如果只用新算法比对，所有老规则都会被误判成"用户改过"而不再升级。
    所以保留旧算法，两个都认。
    """
    return _fingerprint(rule, normalize_sources=False)


def _fingerprint(rule, normalize_sources=True):
    import hashlib

    keys = ("name", "severity", "action", "match_mode", "keywords",
            "regex", "exclude", "note")
    payload = {}
    for key in keys:
        value = rule.get(key)
        if key in ("keywords", "regex", "exclude"):
            value = list(value or [])
        payload[key] = value
    if normalize_sources:
        payload["sources"] = _normalize_sources(rule.get("sources"))
    else:
        payload["sources"] = list(rule.get("sources") or [])
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _is_pristine(existing):
    """内容是否与我们上次写入时完全一致（用户没动过）。"""
    stored = existing.get("_builtin_hash")
    if not stored:
        return False
    return stored in (_content_fingerprint(existing),
                     _fingerprint_legacy(existing))


def _stamp_builtin(rule):
    """给内置规则打上内容指纹，便于下次升级判断"是否被用户改过"。"""
    stamped = copy.deepcopy(rule)
    stamped["_builtin_hash"] = _content_fingerprint(rule)
    return stamped


def _looks_like_older_builtin(existing, template):
    r"""无指纹的历史文件：用子集关系判断是不是我们的旧版本。

    仅适用于"早期版本写下的规则"（那时还没有内容指纹）。判据：

    * 现有关键词/正则/抑制项都必须能在模板里找到 → 否则说明是用户加的
    * 匹配方式 / 级别 / 动作 一致 → 否则说明是用户改的

    比较时做空白归一化：模板演进过（比如 ``update`` 改成 ``update ``、
    ``\bdel\b\s+/[a-z]\b`` 去掉尾部 ``\b``），这类差异不是用户编辑，
    不该因此拒绝升级。
    """
    def _norm(text):
        return " ".join(str(text).split()).rstrip("\\b")

    for key in ("keywords", "regex", "exclude"):
        current = {_norm(x) for x in (existing.get(key) or [])}
        target = {_norm(x) for x in (template.get(key) or [])}
        if current - target:
            return False           # 用户加了模板里没有的东西 → 视为已编辑
    for key in ("match_mode", "severity", "action"):
        if existing.get(key) not in (None, template.get(key)):
            return False
    return True


def migrate_document(doc):
    """把新版内置规则合并进已有 rules.json。

    为什么需要：用户已经装了旧版，rules.json 就存在了，
    ``write_defaults_if_missing`` 不会覆盖它 —— 结果新增/修正的内置规则
    （比如补的删除变种）永远到不了老用户手里。

    策略（每项都先判断用户是否动过）：
    * ``defaults_rev`` 记录内置规则版本，只在变新时迁移
    * 内置有、用户文件没有的规则 → 补齐
    * 内置规则被我们增强了、且用户没改过它 → 更新（改过则保留用户的）
      判断依据是 ``_builtin_hash`` 内容指纹，而不是简单地"存在就跳过"
    * 用户删掉的默认规则记在 ``removed_defaults``，不再重复添加
    """
    if not isinstance(doc, dict):
        return doc, False

    try:
        current_rev = int(doc.get("defaults_rev") or 0)
    except (TypeError, ValueError):
        current_rev = 0
    if current_rev >= DEFAULTS_REV:
        return doc, False

    removed = set(doc.get("removed_defaults") or [])
    rules = doc.setdefault("rules", [])
    by_id = {}
    for index, rule in enumerate(rules):
        if isinstance(rule, dict):
            by_id.setdefault(rule.get("id"), index)

    added, updated = [], []
    for default_rule in DEFAULT_RULES:
        rule_id = default_rule.get("id")
        if not rule_id or rule_id in removed:
            continue

        existing_index = by_id.get(rule_id)
        if existing_index is None:
            rules.append(_stamp_builtin(default_rule))
            added.append(rule_id)
            continue

        existing = rules[existing_index]
        if existing.get("_builtin_hash"):
            # 有指纹：内容与指纹一致 = 用户没动过 → 可安全升级
            pristine = _is_pristine(existing)
        else:
            # 历史文件没有指纹：退化为子集判断
            pristine = _looks_like_older_builtin(existing, default_rule)

        if not pristine:
            continue                # 用户改过 → 尊重用户版本

        merged = _stamp_builtin(default_rule)
        merged["enabled"] = existing.get("enabled",
                                         default_rule.get("enabled", True))
        rules[existing_index] = merged
        updated.append(rule_id)

    allow = doc.setdefault("allowlist", [])
    allow_ids = {a.get("id") for a in allow if isinstance(a, dict)}
    for default_allow in DEFAULT_ALLOWLIST:
        entry_id = default_allow.get("id")
        if entry_id in allow_ids or entry_id in removed:
            continue
        allow.append(copy.deepcopy(default_allow))

    settings = doc.setdefault("settings", {})
    for key, value in DEFAULT_SETTINGS.items():
        settings.setdefault(key, copy.deepcopy(value))

    doc["defaults_rev"] = DEFAULTS_REV
    doc["migrated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return doc, bool(added or updated)


# ---------------------------------------------------------------- 校验

def _coerce_list(value, name, rule_id):
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (str, int, float)):
                text = str(item).strip()
                if text:
                    out.append(text)
        return out
    raise ValueError("规则 %s 的 %s 必须是字符串或数组" % (rule_id, name))


def _compile_regex_list(patterns, rule_id, field):
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.I))
        except re.error as exc:
            raise ValueError("规则 %s 的 %s 正则非法 (%s): %s" % (rule_id, field, pat, exc))
    return compiled


def validate_rule(raw):
    """校验并规整单条规则，返回 (ok, rule_or_error)。"""
    if not isinstance(raw, dict):
        return False, "规则必须是对象"

    rule = dict(raw)
    rule_id = str(rule.get("id") or "").strip() or "R-" + uuid.uuid4().hex[:6].upper()
    rule["id"] = rule_id

    name = str(rule.get("name") or "").strip()
    if not name:
        return False, "规则 %s 缺少 name" % rule_id
    rule["name"] = name

    severity = str(rule.get("severity") or "medium").lower()
    if severity not in VALID_SEVERITIES:
        return False, "规则 %s 的 severity 非法：%s" % (rule_id, severity)
    rule["severity"] = severity

    action = str(rule.get("action") or "block").lower()
    if action not in VALID_ACTIONS:
        return False, "规则 %s 的 action 非法：%s" % (rule_id, action)
    rule["action"] = action

    mode = str(rule.get("match_mode") or "substring").lower()
    if mode not in VALID_MATCH_MODES:
        return False, "规则 %s 的 match_mode 非法：%s" % (rule_id, mode)
    rule["match_mode"] = mode

    try:
        keywords = _coerce_list(rule.get("keywords"), "keywords", rule_id)
        patterns = _coerce_list(rule.get("regex"), "regex", rule_id)
        excludes = _coerce_list(rule.get("exclude"), "exclude", rule_id)
        sources = _coerce_list(rule.get("sources"), "sources", rule_id)
    except ValueError as exc:
        return False, str(exc)

    if not keywords and not patterns:
        return False, "规则 %s 至少要有一个 keyword 或 regex" % rule_id

    if sources:
        bad = [s for s in sources if s not in ALL_SOURCES]
        if bad:
            return False, "规则 %s 的 sources 含非法值：%s" % (rule_id, ",".join(bad))
    # 空 sources 保持为空 = "全部字段"。不展开成完整列表：这样以后新增
    # 扫描维度时，老规则会自动覆盖到，不需要用户逐条重新编辑。
    else:
        sources = []

    if mode == "regex" or patterns:
        try:
            _compile_regex_list(patterns, rule_id, "regex")
        except ValueError as exc:
            return False, str(exc)

    try:
        _compile_regex_list(excludes, rule_id, "exclude")
    except ValueError as exc:
        return False, str(exc)

    rule["keywords"] = keywords
    rule["regex"] = patterns
    rule["exclude"] = excludes
    rule["sources"] = sources
    rule["enabled"] = bool(rule.get("enabled", True))
    rule["note"] = str(rule.get("note") or "")
    # 内置规则内容指纹：迁移时用来判断用户是否改过这条规则。
    # 校验阶段必须原样保留，否则每次加载都当成"被改过"。
    if rule.get("_builtin_hash"):
        rule["_builtin_hash"] = str(rule["_builtin_hash"])
    return True, rule


def validate_document(doc):
    """校验整份文档，返回 (ok, doc_or_error)。"""
    if not isinstance(doc, dict):
        return False, "规则文件根节点必须是对象"

    out = {
        "version": doc.get("version", 1),
        "defaults_rev": doc.get("defaults_rev", 0),
        "removed_defaults": list(doc.get("removed_defaults") or []),
        "settings": copy.deepcopy(DEFAULT_SETTINGS),
        "allowlist": [],
        "rules": [],
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if doc.get("migrated_at"):
        out["migrated_at"] = doc["migrated_at"]

    settings = doc.get("settings")
    if isinstance(settings, dict):
        for key in DEFAULT_SETTINGS:
            if key in settings:
                out["settings"][key] = settings[key]
    mode = str(out["settings"].get("mode", "block")).lower()
    if mode not in ("block", "monitor"):
        return False, "settings.mode 只能是 block 或 monitor"
    out["settings"]["mode"] = mode
    fail_mode = str(out["settings"].get("fail_mode", "closed")).lower()
    out["settings"]["fail_mode"] = fail_mode if fail_mode in ("closed", "open") else "closed"

    raw_allow = doc.get("allowlist") or []
    if not isinstance(raw_allow, list):
        return False, "allowlist 必须是数组"
    seen_ids = set()
    for item in raw_allow:
        if not isinstance(item, dict):
            return False, "allowlist 条目必须是对象"
        pattern = str(item.get("pattern") or "").strip()
        if not pattern:
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            return False, "放行名单正则非法 (%s)：%s" % (pattern, exc)
        entry = {
            "id": str(item.get("id") or ("A-" + uuid.uuid4().hex[:6].upper())),
            "enabled": bool(item.get("enabled", True)),
            "source": str(item.get("source") or "any"),
            "pattern": pattern,
            "note": str(item.get("note") or ""),
        }
        if entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        out["allowlist"].append(entry)

    raw_rules = doc.get("rules") or []
    if not isinstance(raw_rules, list):
        return False, "rules 必须是数组"
    seen_ids = set()
    for raw in raw_rules:
        ok, result = validate_rule(raw)
        if not ok:
            return False, result
        if result["id"] in seen_ids:
            result["id"] = "R-" + uuid.uuid4().hex[:6].upper()
        seen_ids.add(result["id"])
        out["rules"].append(result)
    return True, out


# ---------------------------------------------------------------- 读写

def load_document(path=None):
    """读取规则文件；不存在或损坏时返回默认文档（不覆盖磁盘）。

    顺带做一次内置规则迁移：旧版 rules.json 会自动补齐新增的默认规则。
    """
    path = path or config.rules_path()
    if not os.path.exists(path):
        return default_document()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (ValueError, OSError):
        # 损坏文件先备份，避免用户规则被静默清空
        try:
            backup = path + ".broken." + time.strftime("%Y%m%d%H%M%S")
            os.replace(path, backup)
        except OSError:
            pass
        return default_document()
    ok, result = validate_document(raw)
    if not ok:
        return default_document()

    merged, changed = migrate_document(result)
    if changed:
        try:
            save_document(merged, path)
        except (ValueError, OSError):
            return merged
    return merged


def update_document(mutate, path=None):
    """原子地「读 → 改 → 写」rules.json，跨进程互斥。

    为什么必须有这个函数（实测发现，实测复现丢失更新）：
    各处原来的写法都是

        doc = load_document(path)
        ...改 doc...
        save_document(doc, path)

    只给 save_document 加文件锁**挡不住**这个问题 —— 锁只覆盖写入
    那一刻，而"读"发生在锁外。两个进程各读到同一份旧内容，
    后写者照样整体覆盖前者的改动。

    实测：A 关掉 R-101、B 暂停整体（两个真实子进程，中间 sleep），
    最终 settings.enabled 回到 True —— B"写入成功"了却完全没效果。

    所以互斥必须覆盖**整个读-改-写**。本函数把三步放进同一把文件锁；
    mutate(doc) 的返回值原样返回（方便 API 层拿操作结果）。

    注意：内部用``_write_document_unlocked``直接落盘，**不能**再调
    save_document —— 那会重复获取同一把文件锁，而 _CrossProcessLock
    不是可重入的（实测：拿到锁后再取一次必抛 PermissionError，
    重试到超时后 fail-open，等于锁白加了）。
    """
    path = path or config.rules_path()
    with _lock:
        with _CrossProcessLock(path):
            doc = load_document(path)
            result = mutate(doc)
            _write_document_unlocked(doc, path)
            return result


def _write_document_unlocked(doc, path):
    """校验 + 原子写入。**调用方必须已持有写锁**。

    从 save_document 拆出来的，给 update_document 复用
    （它已经持有锁，不能再走 save_document 的加锁路径）。
    """
    ok, result = validate_document(doc)
    if not ok:
        raise ValueError(result)
    result["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return result


def save_document(doc, path=None):
    path = path or config.rules_path()
    config.ensure_dirs()
    # 线程锁（同进程）+ 文件锁（跨进程）——两层都要。
    #
    # 注意：本函数只保护"写入"这一段。如果调用方是
    # 「先 load 再 save」，中间那段窗口仍可能被别人插队 ——
    # 那种场景请用 update_document()（它把读写放进同一把锁）。
    with _lock:
        with _CrossProcessLock(path):
            return _write_document_unlocked(doc, path)


def write_defaults_if_missing(path=None):
    path = path or config.rules_path()
    if not os.path.exists(path):
        return save_document(default_document(), path)
    return load_document(path)


# ---------------------------------------------------------------- 增删改

def check_redos(patterns, label="正则"):
    """检查一批正则是否疑似灾难性回溯（ReDoS）。

    只在**用户新增/编辑规则**时调用（upsert_rule / upsert_allow），
    不在每次加载时跑 —— 探测要起子进程，放热路径上不可接受。

    为什么必须查 exclude 和 allowlist（实测发现的漏洞）：
    exclude 在**每个命中点**上跑、allowlist.pattern 在**每个字段**上跑，
    一条病态正则和病态 rule["regex"] 一样能把请求拖死；而之前只检查了
    rule["regex"]（实测 validate_rule(exclude=['(a+)+$']) 返回 True，
    upsert_allow('(a+)+$') 也照收）。

    探测不可用时返回空（不阻断保存）—— 不能因为检测器故障让用户
    没法编辑规则。
    """
    if not patterns:
        return
    try:
        from .regexguard import check_patterns as _check_patterns
        bad = _check_patterns(list(patterns))
    except Exception:
        return
    if bad:
        pattern, reason = next(iter(bad.items()))
        raise ValueError(
            "%s疑似灾难性回溯（ReDoS，会让每个请求卡死）：%s → %s"
            % (label, pattern[:60], reason[:80]))


def upsert_rule(doc, rule):
    ok, result = validate_rule(rule)
    if not ok:
        raise ValueError(result)
    # 存盘前做 ReDoS 深度检查（regex + exclude 都查）
    check_redos(list(result.get("regex") or [])
                + list(result.get("exclude") or []), "规则 %s 的正则"
                % result.get("id", "?"))
    # 用户在 UI / API 里保存规则 = 这条规则归他管了。去掉内置指纹，
    # 之后的版本升级就不会再用新模板覆盖他的调整。
    existing = None
    for item in doc.setdefault("rules", []):
        if item.get("id") == result["id"]:
            existing = item
            break
    if existing is not None:
        builtin_hash = existing.get("_builtin_hash")
        if builtin_hash:
            # 两边都归一化后比较：用户只是打开又保存（字段范围写法从
            # "显式列出" 变成 "留空=全部"）不该被当成定制。
            unchanged = (_content_fingerprint(existing)
                         == _content_fingerprint(result))
            if unchanged:
                result["_builtin_hash"] = builtin_hash
            else:
                result.pop("_builtin_hash", None)   # 真改了 → 用户定制版
    else:
        result.pop("_builtin_hash", None)

    rules = doc.setdefault("rules", [])
    for idx, item in enumerate(rules):
        if item.get("id") == result["id"]:
            rules[idx] = result
            return result
    rules.append(result)
    return result


def delete_rule(doc, rule_id):
    """删除规则。若删的是内置规则，记进 removed_defaults —— 否则下次
    加载时的迁移逻辑会把它当成"缺失的内置规则"又加回来。"""
    rules = doc.setdefault("rules", [])
    before = len(rules)
    doc["rules"] = [r for r in rules if r.get("id") != rule_id]
    deleted = before != len(doc["rules"])
    if deleted and any(d.get("id") == rule_id for d in DEFAULT_RULES):
        removed = doc.setdefault("removed_defaults", [])
        if rule_id not in removed:
            removed.append(rule_id)
    return deleted


def toggle_rule(doc, rule_id, enabled):
    for rule in doc.setdefault("rules", []):
        if rule.get("id") == rule_id:
            rule["enabled"] = bool(enabled)
            return True
    return False


def upsert_allow(doc, entry):
    pattern = str(entry.get("pattern") or "").strip()
    if not pattern:
        raise ValueError("pattern 不能为空")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError("正则非法：%s" % exc)
    # 白名单正则在每个字段上跑，病态的同样能拖死请求 —— 存盘前查一次
    check_redos([pattern], "放行名单 %s 的正则"
                % (entry.get("id") or pattern[:24]))
    result = {
        "id": str(entry.get("id") or ("A-" + uuid.uuid4().hex[:6].upper())),
        "enabled": bool(entry.get("enabled", True)),
        "source": str(entry.get("source") or "any"),
        "pattern": pattern,
        "note": str(entry.get("note") or ""),
    }
    items = doc.setdefault("allowlist", [])
    for idx, existing in enumerate(items):
        if existing.get("id") == result["id"]:
            items[idx] = result
            return result
    items.append(result)
    return result


def delete_allow(doc, allow_id):
    items = doc.setdefault("allowlist", [])
    before = len(items)
    doc["allowlist"] = [a for a in items if a.get("id") != allow_id]
    return before != len(doc["allowlist"])
