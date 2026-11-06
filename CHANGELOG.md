# 更新记录

版本号规则：`主.次.修`。拦截面、规则集或安全相关改动进次版本号，其余进修订号。

## 1.1.13 — 2026-10-16

- 修复代理 gzip：解压后超过扫描上限改为 413，不再只扫前一段却转发全部
- 修复代理 gzip：解压结果只用于扫描，转发仍用原始压缩字节
  （此前把头保留、body 换成明文，正常的 gzip 请求会被打坏）
- 代理增加并发连接上限（96），避免慢速 CONNECT 堆积线程
- 叶证书内存缓存加上限（128），超限丢弃最早的一半
- `certs.py` 不再使用已弃用的 `datetime.utcnow()`
- 移除 `runner.py` 中未使用的变量
- USAGE 补充：心跳 20 秒窗口的含义、事件库明文的清除方式

## 1.1.12 — 2026-10-16

- README 精简为项目说明、下载安装、作者、免责声明
- USAGE.md 收敛为安装、通道、开关、规则、命令、边界、卸载、排查
- 移除 docs/DESIGN.md

## 1.1.11 — 2026-10-16

- curl：命令行 `-H @file` / `-b @file` / `--url-query @file` 读取文件内容；
  `-o` / `-D` / `-w` / `--output-dir` 等本地输出选项不再进入扫描面
- 配置文件：`connect-to` / `resolve` 纳入判定；位置参数中的单标签主机
  （`metadata/delete`）按 URL 处理
- 扫描上限：`unlock` 窗口与请求级白名单可放行超限请求；
  `/api/scan` 文本模式与 `wafctl check` 文本模式超限改为明确报错
- 新增 `waf/bodycodec.py`：gzip / deflate 请求体解压后扫描，
  br / zstd / 损坏 / 解压后超过 8MB 一律拒绝
- 性能：归一化按需执行、上游 TLS 上下文缓存
  （256KB 请求体约 1.06s → 0.41s，64KB 约 269ms → 108ms）

## 1.1.10 — 2026-10-16

- 多 URL 请求下 host 白名单生效；额外 URL 纳入扫描面
- 无 scheme 与单标签主机 URL 纳入 `urls`
- 配置文件中的 `url` 参与白名单判定；`data=@file`、`header=@file`、
  嵌套 `config` 递归读取
- guard 与代理统一使用 `max_scan_bytes`，超限拒绝
- `-K -` 不再静默截断
- `.curlrc` 注释不再当作请求内容（修复误报）
- 代理 CONNECT 在引擎异常时按 `fail_mode` 处理
- 测试：`test_waf.py` 拆分为 `test_waf_core/guard/rules` 三个文件

## 1.1.9 — 2026-10-16

- `source=host` 白名单按主机名匹配
- 多个 `--url` 全部收集，不再只保留最后一个
- 读取 curl 默认配置文件（`~/.curlrc`、`%APPDATA%\_curlrc` 等），
  首参 `-q` 时跳过
- 扫描字节与发送字节一致：`@file`、`@-`、代理 body 超限一律拒绝
- 代理引擎异常按 `fail_mode` 处理，不再 fail-open
- 命令门槛词表随规则文件变化失效，并派生自生效规则
- settings 逐项校验类型与范围，非法值回退默认
- `strip_sql_comment` 在带映射变体中生效，注释替换为空格
- 自身接口豁免要求明确的 `/api/` 路径

## 1.1.8 — 2026-10-16

- 新增 `uninstall.bat`：撤销全部接入并复核结果，可选删除 `data/` 与目录
- `wafctl uninstall-path` 增加 `--purge-data`；卸载后调用 `verify_clean()` 复核
- 无人值守卸载：`WAF_UNINSTALL=yes|purge|all`
- 修复：批处理块内括号未转义导致"保留 data"分支报错；提问顺序调整到 `call` 之前

## 1.1.7 — 2026-10-16

- README 精简为工具介绍、下载安装、作者、免责声明四部分
- 完整说明移至 `USAGE.md`

## 1.1.6 — 2026-10-16

- 新增传输层拦截：`http.client` 与裸 socket（含 `sendall` / `send`）
- 修复 `urllib` 的 `Request(data=...)` body 未被检查
- R-102 补充 `TRUNCATE <表名>`、`FLUSHDB`、`dropDatabase` / `drop_collection`
- 新增 R-107（拦截）：`GRANT … TO`、`REVOKE … FROM`、`ALTER TABLE … DROP`、
  `ALTER USER … PASSWORD`
- PowerShell：包装 `Invoke-WebRequest` / `Invoke-RestMethod`，检查逻辑在 `waf/pshook.py`
- 修复补丁重复叠加（一次 `requests.get` 曾被扫 36 次）
- 修复引擎冷启动时 `_check_cmd → get_engine → 探测子进程` 的递归
- 同一请求跨多层挂钩只扫描一次（`contextvars` 飞行指纹）
- `wafctl test` 改为子进程 + `HUNTGUARD_NO_HOOK=1`，避免与运行中的控制台相互干扰

## 1.1.5 — 2026-10-15

- 修复 Python 通道完全失效：`autohook._guess_root()` 优先读取
  `HUNTGUARD_HOME` / `AGENTWAF_HOME`

## 1.1.4 — 2026-10-15

- 动作位匹配：`delete` / `remove` / `purge` 等仅在分隔符后判定，
  放行 `deleted_at`、`is_deleted` 等软删除字段
- 归一化：URL 编码、HTML 实体、Unicode 转义、全角、零宽字符、分隔符拆字
- 搜索参数中的自然语言描述放行，SQL 语法仍拦截
- 四条接入通道：curl shim、BASH_ENV、PowerShell profile、PYTHONPATH 钩子
- ReDoS 防护：病态正则加载时子进程探测并设超时
- 代理上游 TLS 默认校验；MITM 叶私钥用完即删
- `--connect-to` / `--resolve` 的真实主机参与白名单判定
- 跨进程写锁：控制台与 CLI 并发修改规则不会互相覆盖

## 1.0.0 — 2026-10-13

首个版本：规则引擎、curl 拦截、本地控制台、规则热重载。
