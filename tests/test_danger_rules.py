# -*- coding: utf-8 -*-
"""R-3xx 高危操作规则自测：脱库 / 后门 / 云资源删除等。

这些规则的设计难点不在"拦得住"，而在**不误拦**：
挖洞时读日志、读配置、列权限、跑扫描器全都是正常工作。
所以每个用例都成对写：危险的必须拦，正常的必须放行。
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf.engine import RuleEngine                            # noqa: E402
from waf.models import ScanTarget                            # noqa: E402


def _scan(url="", body="", raw_cmd=""):
    from urllib.parse import urlsplit
    target = ScanTarget(kind="request", method="GET", url=url, body=body,
                        raw_cmd=raw_cmd, tool="test")
    if url:
        parts = urlsplit(url)
        target.host, target.path, target.query = (parts.netloc, parts.path,
                                                  parts.query)
    return RuleEngine().scan(target, log=False)


class DangerRulesMixin(object):
    """便于成对写正反用例。"""

    def assert_block(self, label, **kwargs):
        verdict = _scan(**kwargs)
        self.assertTrue(
            verdict.blocked,
            "应拦截但放行：%s（规则=%s）"
            % (label, [h.rule_id for h in verdict.hits]))

    def assert_allow(self, label, **kwargs):
        verdict = _scan(**kwargs)
        self.assertFalse(
            verdict.blocked,
            "不应拦截：%s（命中=%s）"
            % (label, [(h.rule_id, h.keyword) for h in verdict.hits]))


# ====================================================================
# R-301 脱库 / 数据外带
# ====================================================================

class TestDataExfiltration(DangerRulesMixin, unittest.TestCase):

    def test_real_dumps_blocked(self):
        self.assert_block("mysqldump 带参数", raw_cmd="mysqldump -u root -p pw db")
        self.assert_block("mysqldump 重定向", raw_cmd="mysqldump db > /tmp/a.sql")
        self.assert_block("pg_dump", raw_cmd="pg_dump -h host -U admin mydb")
        self.assert_block("pg_dumpall", raw_cmd="pg_dumpall -U postgres")
        self.assert_block("mongodump", raw_cmd="mongodump --uri mongodb://x")
        self.assert_block("INTO OUTFILE",
                          body="SELECT * FROM users INTO OUTFILE '/tmp/a'")
        self.assert_block("sqlmap --dump-all",
                          raw_cmd="sqlmap -u http://x --dump-all")

    def test_reading_docs_not_blocked(self):
        """只在文档/搜索里提到工具名，不是脱库。"""
        self.assert_allow("帮助页 URL",
                          url="http://x/docs?page=mysqldump-guide")
        self.assert_allow("sqlmap 常规探测",
                          raw_cmd="sqlmap -u http://x/?id=1 --batch")
        self.assert_allow("pg_dump 出现在搜索词",
                          url="http://x/search?q=pg_dump+usage")


# ====================================================================
# R-302 后门 / 持久化
# ====================================================================

class TestBackdoor(DangerRulesMixin, unittest.TestCase):

    def test_backdoor_blocked(self):
        self.assert_block("写 authorized_keys",
                          raw_cmd="echo 'ssh-rsa AAA' >> ~/.ssh/authorized_keys")
        self.assert_block("一句话马 eval($_POST)",
                          body="<?php eval($_POST['x']); ?>")
        self.assert_block("一句话马 system($_GET)",
                          body="<?php system($_GET['c']); ?>")
        self.assert_block("crontab 编辑", raw_cmd="crontab -e")
        self.assert_block("schtasks", raw_cmd="schtasks /create /tn x /tr y")
        self.assert_block("新建用户", raw_cmd="useradd -m backdoor")
        self.assert_block("net user /add",
                          raw_cmd="net user hacker P@ss /add")
        self.assert_block("写 .bashrc",
                          raw_cmd="echo 'evil' >> ~/.bashrc")

    def test_listing_not_blocked(self):
        """列出计划任务 / 查看配置不是留后门。"""
        self.assert_allow("crontab -l", raw_cmd="crontab -l")
        self.assert_allow("schtasks 查询", raw_cmd="schtasks /query /tn x")
        self.assert_allow("net user 查看", raw_cmd="net user")
        self.assert_allow("查看 bashrc", raw_cmd="cat ~/.bashrc")


# ====================================================================
# R-303 痕迹清理
# ====================================================================

class TestAntiForensics(DangerRulesMixin, unittest.TestCase):

    def test_clearing_blocked(self):
        self.assert_block("history -c", raw_cmd="history -c")
        self.assert_block("清空 HISTFILE", raw_cmd="unset HISTFILE")
        self.assert_block("删日志", raw_cmd="rm -rf /var/log/nginx")
        self.assert_block("清空日志重定向", raw_cmd="> /var/log/auth.log")
        self.assert_block("Windows 清事件日志", raw_cmd="wevtutil cl System")
        self.assert_block("关审计", raw_cmd="auditctl -e 0")
        self.assert_block("关 SElinux", raw_cmd="setenforce 0")

    def test_reading_logs_not_blocked(self):
        """读日志是正常渗透步骤（尤其 LFI 场景）。"""
        self.assert_allow("LFI 读 access.log",
                          url="http://x/?file=/var/log/nginx/access.log")
        self.assert_allow("cat 日志", raw_cmd="cat /var/log/syslog")
        self.assert_allow("tail -f 日志", raw_cmd="tail -f /var/log/syslog")
        self.assert_allow("grep 日志", raw_cmd="grep FAIL /var/log/auth.log")
        self.assert_allow("读 bash_history", raw_cmd="cat ~/.bash_history")


# ====================================================================
# R-304 云 / 容器 / IaC
# ====================================================================

class TestCloudDestruction(DangerRulesMixin, unittest.TestCase):

    def test_destructive_blocked(self):
        self.assert_block("kubectl delete", raw_cmd="kubectl delete ns prod")
        self.assert_block("helm uninstall", raw_cmd="helm uninstall myapp")
        self.assert_block("terraform destroy", raw_cmd="terraform destroy")
        self.assert_block("docker system prune", raw_cmd="docker system prune -a")
        self.assert_block("docker volume rm", raw_cmd="docker volume rm data")
        self.assert_block("docker rm -f", raw_cmd="docker rm -f web")
        self.assert_block("aws s3 rb", raw_cmd="aws s3 rb s3://b --force")
        self.assert_block("aws ec2 terminate",
                          raw_cmd="aws ec2 terminate-instances --ids i-1")
        self.assert_block("gcloud delete",
                          raw_cmd="gcloud compute instances delete vm-1")

    def test_readonly_not_blocked(self):
        self.assert_allow("kubectl get", raw_cmd="kubectl get pods -A")
        self.assert_allow("kubectl describe",
                          raw_cmd="kubectl describe pod web-1")
        self.assert_allow("docker ps", raw_cmd="docker ps -a")
        self.assert_allow("docker logs", raw_cmd="docker logs web")
        self.assert_allow("terraform plan", raw_cmd="terraform plan")
        self.assert_allow("helm list", raw_cmd="helm list -A")
        self.assert_allow("aws describe",
                          raw_cmd="aws ec2 describe-instances")


# ====================================================================
# R-305 备份 / 快照删除
# ====================================================================

class TestBackupDeletion(DangerRulesMixin, unittest.TestCase):

    def test_blocked(self):
        self.assert_block("vssadmin 删影卷",
                          raw_cmd="vssadmin delete shadows /all /quiet")
        self.assert_block("wbadmin 删备份", raw_cmd="wbadmin delete catalog")
        self.assert_block("删云快照",
                          raw_cmd="aws ec2 delete-snapshot --snapshot-id s-1")
        self.assert_block("LV 删除", raw_cmd="lvremove /dev/vg/data")
        self.assert_block("删备份目录", raw_cmd="rm -rf /backup/db")

    def test_listing_not_blocked(self):
        self.assert_allow("列快照", raw_cmd="aws ec2 describe-snapshots")
        self.assert_allow("跨平台备份",
                          raw_cmd="rsync -av /data/ /backup/data/")


# ====================================================================
# R-306 权限 / 账号体系
# ====================================================================

class TestPrivilegeDestruction(DangerRulesMixin, unittest.TestCase):

    def test_writing_blocked(self):
        self.assert_block(">> sudoers",
                          raw_cmd="echo 'a ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")
        self.assert_block("tee sudoers",
                          raw_cmd="echo x | tee -a /etc/sudoers")
        self.assert_block("sed -i sudoers",
                          raw_cmd="sed -i s/^/#/ /etc/sudoers")
        self.assert_block("覆盖 passwd", raw_cmd="cp /tmp/fake /etc/passwd")
        self.assert_block("mv 覆盖 shadow", raw_cmd="mv /tmp/x /etc/shadow")
        self.assert_block("sudoers.d",
                          raw_cmd="echo x > /etc/sudoers.d/evil")
        self.assert_block("加 sudo 组",
                          raw_cmd="usermod -aG sudo hacker")
        self.assert_block("chmod -R 系统目录",
                          raw_cmd="chmod -R 777 /etc")
        self.assert_block("加管理员组",
                          raw_cmd="net localgroup administrators hacker /add")

    def test_reading_not_blocked(self):
        """读配置 / 列权限是提权检查的常规动作，必须放行。"""
        self.assert_allow("cat sudoers", raw_cmd="cat /etc/sudoers")
        self.assert_allow("grep NOPASSWD",
                          raw_cmd="grep -i nopasswd /etc/sudoers")
        self.assert_allow("cat shadow", raw_cmd="cat /etc/shadow")
        self.assert_allow("拷出来审计",
                          raw_cmd="cp /etc/sudoers /tmp/audit/")
        self.assert_allow("icacls 列权限", raw_cmd="icacls C:\\inetpub")
        self.assert_allow("ls -l etc", raw_cmd="ls -l /etc/")
        self.assert_allow("查看组", raw_cmd="net localgroup administrators")


# ====================================================================
# R-307 防火墙 / 安全组件
# ====================================================================

class TestSecurityDisable(DangerRulesMixin, unittest.TestCase):

    def test_blocked(self):
        self.assert_block("iptables -F", raw_cmd="iptables -F")
        self.assert_block("iptables -X", raw_cmd="iptables -X")
        self.assert_block("iptables -P DROP",
                          raw_cmd="iptables -P INPUT DROP")
        self.assert_block("ufw disable", raw_cmd="ufw disable")
        self.assert_block("netsh 关防火墙",
                          raw_cmd="netsh advfirewall set allprofiles state off")
        self.assert_block("关 Defender",
                          raw_cmd="Set-MpPreference -DisableRealtimeMonitoring $true")
        self.assert_block("停 sshd", raw_cmd="systemctl stop sshd")
        self.assert_block("停 firewalld",
                          raw_cmd="systemctl disable firewalld")

    def test_readonly_not_blocked(self):
        self.assert_allow("iptables -L", raw_cmd="iptables -L -n -v")
        self.assert_allow("iptables -S", raw_cmd="iptables -S")
        self.assert_allow("ufw status", raw_cmd="ufw status verbose")
        self.assert_allow("systemctl status",
                          raw_cmd="systemctl status nginx")
        self.assert_allow("systemctl restart 业务",
                          raw_cmd="systemctl restart nginx")


# ====================================================================
# R-308 服务中断 / 资源耗尽
# ====================================================================

class TestResourceExhaustion(DangerRulesMixin, unittest.TestCase):

    def test_blocked(self):
        self.assert_block("dd 填盘", raw_cmd="dd if=/dev/zero of=/tmp/big bs=1M")
        self.assert_block("cat 重定向填盘",
                          raw_cmd="cat /dev/zero > /tmp/big")
        self.assert_block("停数据库",
                          raw_cmd="systemctl stop mysqld")
        self.assert_block("kill -9 -1", raw_cmd="kill -9 -1")
        self.assert_block("flood 攻击",
                          raw_cmd="hping3 -S --flood -p 80 10.0.0.1")

    def test_normal_not_blocked(self):
        self.assert_allow("看磁盘", raw_cmd="df -h")
        self.assert_allow("测吞吐（小并发）", raw_cmd="ab -n 100 -c 10 http://x/")
        self.assert_allow("重启服务", raw_cmd="systemctl restart mysqld")


# ====================================================================
# R-310 Git 历史破坏
# ====================================================================

class TestGitHistory(DangerRulesMixin, unittest.TestCase):

    def test_blocked(self):
        self.assert_block("push --force", raw_cmd="git push --force origin main")
        self.assert_block("push -f", raw_cmd="git push -f origin main")
        self.assert_block("reset --hard", raw_cmd="git reset --hard HEAD~3")
        self.assert_block("clean -fdx", raw_cmd="git clean -fdx")
        self.assert_block("filter-branch", raw_cmd="git filter-branch --all")
        self.assert_block("reflog expire", raw_cmd="git reflog expire --all")
        self.assert_block("stash clear", raw_cmd="git stash clear")
        self.assert_block("npm unpublish", raw_cmd="npm unpublish pkg --force")

    def test_normal_git_not_blocked(self):
        self.assert_allow("git push", raw_cmd="git push origin main")
        self.assert_allow("git reset --soft",
                          raw_cmd="git reset --soft HEAD~1")
        self.assert_allow("git clean -n（预览）", raw_cmd="git clean -n")
        self.assert_allow("git stash pop", raw_cmd="git stash pop")
        self.assert_allow("git log", raw_cmd="git log --oneline -20")
        self.assert_allow("git revert", raw_cmd="git revert HEAD")


class TestSelfEndpointExemption(DangerRulesMixin, unittest.TestCase):
    """WAF 控制台自己的 API 不能被自己的规则拦掉。

    踩过的坑：``curl .../api/shutdown`` 命中 R-102 的 shutdown 规则，
    导致控制台关不掉 —— 工具把自己锁死了。判据是"回环主机 + 控制台端口"，
    两个条件都要满足，否则 127.0.0.1 上的靶场会被误放行。
    """

    def test_own_api_exempted(self):
        from waf import config
        cfg = config.load_config()
        port = cfg.get("api_port", config.API_PORT)
        for path in ("/api/shutdown", "/api/rules/delete", "/api/events/clear"):
            verdict = _scan(url="http://127.0.0.1:%d%s" % (port, path))
            self.assertFalse(verdict.blocked,
                             "控制台接口不应被拦：%s" % path)
            self.assertEqual(verdict.stage, "self_endpoint")

    def test_real_target_on_loopback_still_blocked(self):
        """没写端口 = 默认 80，不是控制台端口 → 照常检查（靶场保护）。"""
        self.assert_block("127.0.0.1 上的删除",
                          url="http://127.0.0.1/delete.php")
        self.assert_block("localhost 上的删除",
                          url="http://localhost/delete.php")
        self.assert_block("同机其它端口",
                          url="http://127.0.0.1:8080/api/shutdown")

    def test_remote_target_never_exempted(self):
        self.assert_block("外网目标", url="http://target.com/api?action=remove")


# ====================================================================
# R-309 / R-311 / R-312 / R-313 监控规则：只记录，不拦截
# ====================================================================

class TestMonitorRules(DangerRulesMixin, unittest.TestCase):

    def test_credential_dump_only_monitored(self):
        """授权渗透里凭证转储属正常取证 —— 命中要记录，但不能拦。"""
        for label, cmd in [
            ("mimikatz", "mimikatz.exe privilege::debug"),
            ("procdump lsass", "procdump -ma lsass.exe out.dmp"),
            ("reg save SAM", "reg save HKLM\\SAM sam.hiv"),
            ("ntds.dit", "copy ntds.dit C:\\tmp\\"),
        ]:
            verdict = _scan(raw_cmd=cmd)
            self.assertFalse(verdict.blocked, "不应拦截：%s" % label)
            self.assertTrue(verdict.hits, "应至少记录命中：%s" % label)

    def test_scanners_only_monitored(self):
        for label, cmd in [
            ("nmap", "nmap -sV -p- 10.0.0.1"),
            ("ffuf", "ffuf -u http://x/FUZZ -w dict.txt"),
            ("sqlmap", "sqlmap -u http://x/?id=1 --batch"),
            ("hydra", "hydra -l admin -P pass.txt ssh://10.0.0.2"),
        ]:
            verdict = _scan(raw_cmd=cmd)
            self.assertFalse(verdict.blocked, "不应拦截：%s" % label)
            self.assertTrue(verdict.hits, "应至少记录命中：%s" % label)

    def test_oob_channels_only_monitored(self):
        """证明盲注 / SSRF 必须用外带，拦了没法干活。"""
        for label, url in [
            ("dnslog", "http://x/?u=http://abc.dnslog.cn"),
            ("burp collaborator",
             "http://x/?u=http://x.oastify.com"),
            ("interactsh", "http://x/?u=http://abc.interact.sh"),
        ]:
            verdict = _scan(url=url)
            self.assertFalse(verdict.blocked, "不应拦截：%s" % label)
            self.assertTrue(verdict.hits, "应至少记录命中：%s" % label)

    def test_bulk_select_only_monitored(self):
        """批量 SELECT 偏宽，只记录。"""
        verdict = _scan(url="http://x/api?q=SELECT id,name FROM users WHERE id=1")
        self.assertFalse(verdict.blocked, "批量查询不应拦截")
        self.assertTrue(verdict.hits)


class TestPasswordResetRule(unittest.TestCase):
    """R-314 密码重置 / 账号接管。

    这条规则最难的地方是**不能误拦**：`password` 作为参数名每天出现
    几十次 —— 登录、注册、SQL 注入载荷（`' OR 1=1--`）、爆破字典，
    全是正常挖洞动作。所以判据是「改密动作 + 密码目标」必须**同时**
    出现；单独一个 password= 不拦。

    改密码算不可逆的原因：原凭据立即永久失效。如果改的是目标环境的
    管理员口令而没记下来，等于把目标锁死在外。
    """

    MUST_BLOCK = [
        ("接口 reset-password",
         "http://t/api/user/reset-password?user=admin&pass=123"),
        ("接口 changePassword",
         "http://t/api/user/changePassword?uid=1&newpass=x"),
        ("路径 /password/reset", "http://t/password/reset?token=abc"),
        ("参数 action=resetpass", "http://t/api?action=resetpass&id=1"),
        ("参数 op=changepwd", "http://t/api?op=changepwd&u=admin"),
        ("reset_password 参数", "http://t/api?reset_password=1&user=admin"),
        ("三段式 set_new_password", "http://t/api?set_new_password=abc123"),
        ("三段式 change_user_password",
         "http://t/api?change_user_password=1"),
        ("SQL ALTER USER",
         "http://t/q?sql=ALTER%20USER%20admin%20IDENTIFIED%20BY%20'x'"),
        ("SQL UPDATE password",
         "http://t/q?sql=UPDATE%20users%20SET%20password='x'"),
        ("Linux chpasswd", "http://t/x?cmd=echo 'root:new' | chpasswd"),
        ("Linux passwd root", "http://t/x?cmd=passwd root"),
    ]

    MUST_ALLOW = [
        ("登录", "http://t/api/login?username=admin&password=123456"),
        ("注册", "http://t/api/register?password=abc&confirm=abc"),
        ("SQLi 密码字段", "http://t/api/login?password=' OR 1=1--"),
        ("SQLi SELECT 带 password",
         "http://t/q?sql=SELECT * FROM users WHERE password='x'"),
        ("忘记密码页", "http://t/forgot-password"),
        ("申请重置链接", "http://t/api/request-reset?email=a@b.com"),
        ("token 重置流程", "http://t/reset?token=abc&password=x"),
        ("密码策略查询", "http://t/api/password-policy"),
        ("强度检查", "http://t/api/check-password-strength?p=abc"),
        ("爆破字典", "http://t/api/login?password=admin123"),
        ("软删除字段", "http://t/api?is_deleted=0&password_reset_token=1"),
    ]

    def test_must_block(self):
        missed = []
        for label, url in self.MUST_BLOCK:
            if not _scan(url=url).blocked:
                missed.append(label)
        self.assertEqual(missed, [], "以下改密操作未被拦截：%s" % missed)

    def test_must_allow(self):
        blocked = []
        for label, url in self.MUST_ALLOW:
            if _scan(url=url).blocked:
                blocked.append(label)
        self.assertEqual(blocked, [],
                         "以下正常操作被误拦（password 参数不该拦）：%s" % blocked)

    def test_post_body_covered(self):
        """POST 表单体里的改密也不能漏。"""
        self.assertTrue(
            _scan(url="http://t/api/user",
                  body="action=resetpass&user=admin").blocked)

    def test_plain_password_body_allowed(self):
        """POST 体里只有登录字段时必须放行。"""
        self.assertFalse(
            _scan(url="http://t/api/login",
                  body="username=admin&password=123456").blocked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
