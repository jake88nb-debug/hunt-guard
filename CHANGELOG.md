# 更新记录

版本号规则：`主.次.修`。拦截面变化、规则集变化、安全相关修复 → 提"次"；
仅文档/文案 → 提"修"。

---

## 1.1.4 — 2026-10-15

### 拦截能力

- **动作位匹配**：`delete` / `remove` / `purge` 等动词在分隔符之后才算
  命中（`item_delete`、`user-remove`、`deleteById` 都覆盖），
  同时放行软删除字段（`deleted_at`、`is_deleted`、`deletedAt`）。
- **忽略大小写**：`deleteDraft`、`DeleteRecord` 等命名形态同样命中。
- **归一化绕过防护**：URL 编码、HTML 实体、Unicode 转义、全角、
  零宽字符、分隔符拆字（`d_e_l_e_t_e`）都会被还原后再判定。
- **全部出现位置**：同一字段里敏感词出现多次时逐个检查，
  不会因为第一个落在白名单语境就漏掉后面的。
- **搜索参数豁免**：`?q=how+to+delete+my+account` 这类自然语言描述
  放行，但搜索参数里出现 SQL 语法（`delete from`、`drop table`）仍然拦。

### 四条接入通道

| 通道 | 覆盖范围 |
|---|---|
| curl shim | cmd AutoRun + PATH，拦截命令行 curl |
| BASH_ENV | Git Bash 非交互会话 |
| PowerShell profile | PS 会话里的 curl 调用 |
| PYTHONPATH 钩子 | 普通 Python 进程的 requests / httpx / urllib3 / aiohttp 请求 |

Python 钩子同时覆盖 `subprocess` / `os.system` 调用破坏性命令的情况。

### 安全设计

- **ReDoS 防护**：病态正则在加载时用子进程探测 + 超时挡住，
  不会让每个请求卡死；allowlist 与 exclude 里的正则同样检查。
- **代理上游 TLS 默认校验**，可用 `WAF_PROXY_INSECURE=1` 关闭（打自签靶场）。
- **MITM 叶私钥用完即删**，CA 私钥落盘后收紧 ACL。
- **`--connect-to` / `--resolve` 改写出的真实主机参与白名单判定**，
  不能借白名单主机名把流量引到别处。
- **跨进程写锁**：控制台与独立 CLI 并发改规则时不会互相覆盖。

### 明确的能力边界

这不是安全边界，是**防手滑的护栏**。README 里完整列出了所有逃生开关
（单条环境变量、直接改规则文件等）。用它挡住"AI 顺手执行的不可逆操作"，
不要指望它能拦住有意绕过的对手。

---

## 1.0.0 — 2026-10-13

首个版本：规则引擎 + curl 拦截 + 本地控制台 + 规则热重载。
