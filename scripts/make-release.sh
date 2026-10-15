#!/usr/bin/env bash
# HuntGuard 发布打包：**强制排除 data/**
#
# 为什么必须有这个脚本（实测发现）：README 主推
# "Download ZIP / 解压即用"，而 data/ 里是本机运行时产物 ——
#   ca.key                 CA 私钥（明文）
#   agent-waf-ca.pem       含私钥的合并版
#   events.db + -wal       完整拦截记录（明文 URL / payload）
#   detected.json          本机路径信息
#   rules.json             你自己的规则（可能含靶场域名）
# .gitignore 挡住了 git，但**打包 ZIP 是另一条路** ——
# 手一抖就把私钥和日志一起发出去了。用这个脚本，别手动压缩。
#
# 用法：
#   bash scripts/make-release.sh            # 产出 dist/hunt-guard-<版本>.zip
#   bash scripts/make-release.sh --tar      # 额外产出 .tar.gz（保留可执行位）
#
# 实现说明（踩过的坑）：
#   优先用 **python 的 zipfile** 打包，而不是 Info-ZIP 的 zip 命令。
#   原因：`zip -x` 的模式匹配跨实现有差异 —— Info-ZIP 对
#   `zip -r out.zip .` 存出的条目名**不带 "./" 前缀**（是 data/run/x），
#   于是排除模式写成 "./data" 匹配不上任何条目，data/ 会整包进 zip。
#   本机没有 zip 命令、这条分支从未被执行过，是读代码时发现的。
#   python 的写法（os.walk + 目录裁剪）没有这个歧义，且本机已验证。
#   zip 命令仅作为 python 不可用时的兜底，且排除模式按"无 ./ 前缀"来写。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' waf/config.py | head -1)"
VERSION="${VERSION:-0.0.0}"
NAME="hunt-guard-${VERSION}"
DIST="$ROOT/dist"

mkdir -p "$DIST"
rm -f "$DIST/$NAME.zip" "$DIST/$NAME.tar.gz"

# 绝不能进包的东西。data/ 是重点 —— 它含私钥和拦截日志。
#
# 三层排除：
#   SKIP_TOP    —— 整棵目录不进（python 走 os.walk 裁剪，tar 走 --exclude）
#   SKIP_GLOBS  —— **根目录下的文件名模式**（这一层是补的，见下）
#   zip 模式    —— Info-ZIP 的 -x，条目名不带 "./" 前缀（见文件头说明）
#
# 为什么需要 SKIP_GLOBS（实测发现）：
#   打包走 python 主路径时只用 os.walk 裁**目录**，根目录下的散文件
#   全都会进包。而开发/调试过程中会在仓库根留下 `_verify3.py`、
#   `test_out4.txt`、`git_info.txt` 这类临时文件（.gitignore 挡得住
#   git，但 zipfile 不走 .gitignore）——实测 10 个残留被打了进去，
#   而自检正则只认私钥/事件库，抓不到 → 直接发出去。
SKIP_TOP="data dist .git .github .vscode .idea __pycache__"

# 注意 "_*.py" 会误伤 "__init__.py"（fnmatch 的 * 匹配任意字符，
# 含下划线）—— 那会让整个 waf 包无法导入，包直接报废。
# 实测踩过：打包后 waf/__init__.py 缺失。
# 用 "_[!_]*.py" 表达"下划线开头且第二个字符不是下划线"。
SKIP_GLOBS=(
  "_[!_]*.py"              # 一次性验证/调试脚本（不碰 __init__.py）
  "test_out*.txt" "verify*.txt" "verify*_result.txt" "*_result.txt"
  "bypass_check*.txt" "git_info.txt"
  "*.pyc" "*.log"
)

EXCLUDES_TAR=(
  "data" "dist" ".git" ".github" ".vscode" ".idea"
  "__pycache__" "*.pyc" "*.log"
  "_[!_]*.py" "test_out*.txt" "verify*.txt" "*_result.txt"
  "bypass_check*.txt" "git_info.txt"
)
# Info-ZIP 的 -x 模式：条目名形如 "data/run/active.json"
EXCLUDES_ZIP=(
  "data/*" "dist/*" ".git/*" ".github/*" ".vscode/*" ".idea/*"
  "*/__pycache__/*" "*.pyc" "*.log"
  "_[!_]*.py" "test_out*.txt" "verify*.txt" "*_result.txt"
  "bypass_check*.txt" "git_info.txt"
)

pack_with_python() {
  local py="$1"
  "$py" - "$DIST/$NAME.zip" "$SKIP_TOP" "${SKIP_GLOBS[*]}" <<'PY'
import fnmatch
import os
import sys
import zipfile

out, skip_top, skip_globs = sys.argv[1], set(sys.argv[2].split()), \
    sys.argv[3].split()
SKIP_DIRS = skip_top


def skipped(name):
    return any(fnmatch.fnmatch(name, pat) for pat in skip_globs)


with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for folder, dirs, files in os.walk("."):
        # 目录裁剪：整棵子树直接不进（比逐个文件排除可靠）
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            # 文件名模式（根目录残留与子目录都覆盖）——
            # 光裁目录不够：_verify3.py 这类散在仓库根
            if skipped(name):
                continue
            path = os.path.join(folder, name)
            z.write(path, os.path.relpath(path, "."))
print("    %s" % out)
PY
}

pack_with_zip() {
  local args=()
  for pattern in "${EXCLUDES_ZIP[@]}"; do
    args+=(-x "$pattern")
  done
  zip -r -q "$DIST/$NAME.zip" . "${args[@]}"
  echo "    $DIST/$NAME.zip"
}

echo "==> 打包 $NAME（排除 data/ 与所有缓存）"
PY_BIN="$(command -v python3 || command -v python || true)"
if [ -n "$PY_BIN" ]; then
  pack_with_python "$PY_BIN"
elif command -v zip >/dev/null 2>&1; then
  echo "    [注意] 没找到 python，退化用 zip 命令"
  pack_with_zip
else
  echo "!!! 既没有 python 也没有 zip，无法打包" >&2
  exit 1
fi

if [ "${1:-}" = "--tar" ]; then
  TAR_ARGS=()
  for pattern in "${EXCLUDES_TAR[@]}"; do
    TAR_ARGS+=(--exclude="$pattern")
  done
  tar czf "$DIST/$NAME.tar.gz" "${TAR_ARGS[@]}" .
  echo "    $DIST/$NAME.tar.gz"
fi

# 自检：包里绝不能出现私钥 / 事件库。
# 这是最后一道闸 —— 即使上面的排除规则写错，也不会把私钥发出去。
echo "==> 自检（在包里找私钥与事件库）"
# 自检要认两类东西：
#   1. 敏感文件（私钥 / 事件库 / 本机产物）—— 泄漏风险
#   2. 开发残留（_*.py / test_out*.txt / verify*.txt）—— 不该发布
# 第 2 类以前没查，实测 10 个残留被打了进去而自检不报警
# （实测发现：自检正则只认私钥/事件库）。
SENSITIVE='ca\.key|\.pem|events\.db|detected\.json|rules\.json|active\.json'
RESIDUE='(^|/)_[^/_][^/]*\.py$|(^|/)test_out[^/]*\.txt$|(^|/)verify[^/]*\.txt$|(^|/)bypass_check[^/]*\.txt$|(^|/)git_info\.txt$|__pycache__/|\.pyc$'
if [ -f "$DIST/$NAME.zip" ]; then
  if command -v unzip >/dev/null 2>&1; then
    BAD="$(unzip -l "$DIST/$NAME.zip" \
          | grep -Ei "$SENSITIVE|$RESIDUE" || true)"
  elif [ -n "$PY_BIN" ]; then
    BAD="$("$PY_BIN" -c "
import fnmatch, re, sys, zipfile
sens = re.compile(r'''$SENSITIVE''', re.I)
resi = re.compile(r'''$RESIDUE''')
for n in zipfile.ZipFile(sys.argv[1]).namelist():
    if sens.search(n) or resi.search(n):
        print(n)
" "$DIST/$NAME.zip")"
  else
    BAD=""
  fi
  if [ -n "$BAD" ]; then
    echo "!!! zip 里混进了敏感文件或开发残留，打包中止（不要发布这个包）："
    echo "$BAD"
    exit 1
  fi
fi
if [ -f "$DIST/$NAME.tar.gz" ]; then
  BAD_TAR="$(tar tzf "$DIST/$NAME.tar.gz" \
            | grep -Ei "$SENSITIVE|$RESIDUE" || true)"
  if [ -n "$BAD_TAR" ]; then
    echo "!!! tar.gz 里混进了敏感文件或开发残留，打包中止："
    echo "$BAD_TAR"
    exit 1
  fi
fi
echo "    干净：无私钥、无事件库、无本机规则、无开发残留 ✓"
echo
echo "==> 完成。发布前请再确认："
echo "    unzip -l $DIST/$NAME.zip | head -40"
