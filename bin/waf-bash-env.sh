# HuntGuard: 让 Git Bash / MSYS2 / WSL 的 curl 走拦截器。
#
# 由 BASH_ENV 自动 source —— 非交互 bash（AI 工具执行命令用的就是这种）
# 启动时会读取 BASH_ENV，因此在 ZCode / Claude Code / Codex 等工具的
# shell 会话里同样生效。
#
# 三条硬性要求：
#   1. 静默：任何输出都会污染调用方的脚本，绝不能 echo
#   2. 极快：每次 bash 启动都会跑，只用内建字符串操作，不起子进程
#   3. 幂等且**自愈**：不只是"已存在就跳过"，而是主动把重复条目压成一个
#      —— 历史版本可能在 PATH 里留下过多份（比如旧机制 + 新机制叠加），
#      只做跳过的话那些重复会一直留着
#
# 路径全部从本脚本自身位置推导 —— 装到哪个目录都能用，不需要改脚本。

_src="${BASH_SOURCE[0]:-$0}"
_waf_bin="$(cd "$(dirname "$_src")" 2>/dev/null && pwd)"

# BASH_SOURCE 拿不到时（很罕见）退回环境变量，再不行就静默放弃，
# 绝不猜测硬编码路径 —— 猜错会把别人的 PATH 指到不存在的目录。
# 两个变量名都认：HUNTGUARD_HOME 是正式名，AGENTWAF_HOME 是 1.0 旧名。
if [ -z "$_waf_bin" ] || [ ! -d "$_waf_bin" ]; then
  _waf_home="${HUNTGUARD_HOME:-${AGENTWAF_HOME:-}}"
  if [ -n "$_waf_home" ]; then
    _waf_bin="$(cd "$_waf_home/bin" 2>/dev/null && pwd)"
  fi
fi

if [ -n "$_waf_bin" ] && [ -d "$_waf_bin" ]; then
  # 彻底去重：先剥掉 PATH 里所有本目录，再前置一个。
  # 用 ${var//pat/repl} 内建展开，不 spawn 进程，开销可忽略。
  # 首尾包裹冒号是为了让"第一个/最后一个条目"也能被 :dir: 模式匹配到。
  #
  # 为什么要循环：${var//pat/repl} 是**非重叠**替换，连续重复
  # （如 "A:A"）一轮只能吃掉一个 —— 实测 PATH 里有 3 份时只删掉 1 份，
  # 自愈没做干净。循环到不再变化为止（字符串单调变短，必然终止）。
  _rest=":${PATH}:"
  _prev=""
  while [ "$_rest" != "$_prev" ]; do
    _prev="$_rest"
    _rest="${_rest//":$_waf_bin:"/:}"
  done
  _rest="${_rest#:}"
  _rest="${_rest%:}"
  if [ -n "$_rest" ]; then
    PATH="$_waf_bin:$_rest"
  else
    PATH="$_waf_bin"
  fi
  export PATH
fi
unset _src _waf_bin _rest _prev
