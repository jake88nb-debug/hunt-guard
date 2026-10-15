# -*- coding: utf-8 -*-
"""MITM 证书管理：生成 CA、按域名签发叶证书、导出 .pem/.crt 供导入。

仅在 proxy --mitm 模式下需要。生成的文件放在 data/certs/。
"""

import datetime
import os
import threading

from . import config

_lock = threading.RLock()

CA_KEY = "ca.key"
CA_CERT = "ca.crt"
CA_PEM = "agent-waf-ca.pem"


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        return x509, hashes, serialization, rsa, NameOID
    except ImportError:
        return None


def available():
    return _crypto() is not None


def ensure_ca(common_name="HuntGuard Local CA", years=5):
    """确保 CA 存在，返回 (key_path, cert_path)。"""
    crypto = _crypto()
    if crypto is None:
        raise RuntimeError("需要 cryptography 库：python -m pip install cryptography")
    x509, hashes, serialization, rsa, NameOID = crypto

    config.ensure_dirs()
    key_path = os.path.join(config.CERTS_DIR, CA_KEY)
    cert_path = os.path.join(config.CERTS_DIR, CA_CERT)

    with _lock:
        if os.path.exists(key_path) and os.path.exists(cert_path):
            # 早退分支也必须加固（实测发现）：
            # CA 可能是旧版本生成的（那时权限是继承的默认值，实测
            # Authenticated Users 有修改权限、www/mysql 这类服务账户
            # 能读私钥）。只在"新生成"分支加固的话，存量 CA 永远
            # 停留在弱权限上 —— 而私钥泄露的后果（配合已导入信任库）
            # 是全机 TLS 可被中间人。
            _harden_private(key_path)
            _harden_private(os.path.join(config.CERTS_DIR, CA_PEM))
            _write_security_note()
            return key_path, cert_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HuntGuard"),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365 * years))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256())
        )

        # CA 私钥是本工具权限最高的一件东西：谁拿到它 + 用户把 CA 导入了
        # 信任库，谁就能伪造任意站点的证书、解密这台机器的全部 TLS。
        # 因此：文件权限收紧到 0600（仅本人可读），并写一份 README 说明
        # 它的分量 —— 很多人不知道 ca.pem 里同时含私钥。
        _write_private(key_path, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        # 合并 pem 方便导入 —— 注意它含私钥，权限同样收紧
        _write_private(os.path.join(config.CERTS_DIR, CA_PEM),
                       cert.public_bytes(serialization.Encoding.PEM) +
                       key.private_bytes(
                           encoding=serialization.Encoding.PEM,
                           format=serialization.PrivateFormat.TraditionalOpenSSL,
                           encryption_algorithm=serialization.NoEncryption()))
        _write_security_note()

    return key_path, cert_path


def _write_private(path, data):
    """写私钥文件并尽量收紧访问权限。

    POSIX 上 chmod 0600 就够。Windows 上 os.chmod 只影响只读位，
    对 ACL 无效（实测仍是 0666）—— 必须用 icacls 把继承的权限剥掉，
    只留当前用户。做不到时静默跳过：权限强化失败不该让 MITM 用不了。
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        _restrict_windows_acl(path)


def _harden_private(path):
    """对**已存在**的私钥文件做权限加固（不改内容）。

    与 _write_private 的区别：那个是"写完顺手加固"，只在生成新 CA 时走；
    这个是给存量 CA 补课用的 —— 旧版本生成的密钥权限是继承的默认值
    （实测 Windows 上 Authenticated Users 有 Modify、www/mysql 这类
    服务账户能 Read），不补的话导入信任库后就等于把全机 TLS 交给它们。
    """
    if not path or not os.path.exists(path):
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        _restrict_windows_acl(path)


def _restrict_windows_acl(path):
    """Windows：去掉继承权限，只给当前用户完全控制。

    私钥文件是本工具最敏感的东西（拿到它 + CA 已导入信任库 =
    可解密本机全部 TLS），值得多花一次 subprocess 调用。
    """
    import subprocess
    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        # /inheritance:r 断开继承；/grant:r 只给当前用户
        subprocess.run(
            ["icacls", path, "/inheritance:r",
             "/grant:r", "%s:F" % user],
            capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        pass


def _write_security_note():
    """在证书目录里留一份说明，讲清这几个文件的分量。"""
    note = """\
HuntGuard 证书目录 —— 请读一遍再决定要不要导入
================================================

本目录的文件：

  ca.key                     CA 私钥（明文）。**这是本工具权限最高的一件东西。**
  ca.crt                     CA 证书。导入系统/浏览器信任库用的是它。
  agent-waf-ca.pem           ca.crt + ca.key 合并版（方便导入，但含私钥！）

风险说明
--------
如果你把 CA 导入了系统信任库，那么**任何能读到 ca.key 的进程**都能：
  * 伪造任意网站的证书（包括银行、邮箱）
  * 解密这台机器上的全部 HTTPS 流量

也就是说：这个 CA 一旦导入信任库，本目录的私钥保护级别就等于
你整台机器的 TLS 安全级别。请确认：

  1. 只在做 MITM 抓包时才导入；用完从信任库移除。
  2. 不要把 ca.key / agent-waf-ca.pem 复制到别处、不要提交到 git、
     不要放进共享盘或云同步目录。
  3. 怀疑泄露时：删掉本目录整个 certs/ 文件夹，重新生成一套，
     并从信任库移除旧的 CA。

不需要 MITM 抓包的话，本目录可以直接忽略 —— 普通代理模式
（CONNECT 隧道）不生成也不使用这些文件。
"""
    path = os.path.join(config.CERTS_DIR, "SECURITY-README.txt")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(note)
    except OSError:
        pass


def _load_ca():
    crypto = _crypto()
    x509, hashes, serialization, rsa, NameOID = crypto
    key_path, cert_path = ensure_ca()
    with open(key_path, "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(cert_path, "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())
    return ca_key, ca_cert, x509, hashes, serialization, NameOID


_cache = {}
_cache_lock = threading.RLock()


def leaf_for(hostname, days=825):
    """为 hostname 签发叶证书，返回 (cert_pem_bytes, key_pem_bytes)。"""
    hostname = (hostname or "").strip().lower()
    if not hostname:
        raise ValueError("hostname 不能为空")
    with _cache_lock:
        cached = _cache.get(hostname)
        if cached:
            return cached

    ca_key, ca_cert, x509, hashes, serialization, NameOID = _load_ca()
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    try:
        import ipaddress
        addr = ipaddress.ip_address(hostname)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(addr)]), critical=False)
    except ValueError:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)

    leaf = builder.sign(ca_key, hashes.SHA256())

    cert_pem = leaf.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    result = (cert_pem, key_pem)
    with _cache_lock:
        _cache[hostname] = result
    return result


def ca_paths():
    key_path, cert_path = ensure_ca()
    return {
        "key": key_path,
        "cert": cert_path,
        "combined": os.path.join(config.CERTS_DIR, CA_PEM),
        "dir": config.CERTS_DIR,
        "hint": "把这个 CA 导入系统/浏览器信任库；curl 用 --cacert 指定 ca.crt",
    }
