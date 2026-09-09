"""Stateful Virtual Filesystem (VFS) for the SSH and Telnet honeypot shells.

Provides an in-memory, thread-safe POSIX-like filesystem simulation with
realistic Linux directory trees, standard files, honeypot decoy credentials,
metadata and permissions (chmod/chown), symlinks, and utilities (head, tail, wc,
checksum, tree, grep, find).
"""

from __future__ import annotations

import difflib
import fnmatch
import hashlib
import re
import threading
import time
from typing import Any, Dict, List, Optional

# Resource bounds to prevent denial of service through file inflation
MAX_FILE_SIZE = 5 * 1024 * 1024       # 5 MB per file
MAX_TOTAL_FS_SIZE = 50 * 1024 * 1024  # 50 MB total filesystem


def _mode_to_str(mode: int, is_dir: bool, is_link: bool = False) -> str:
    """Convert numeric octal mode (e.g. 0o755) to POSIX permission string."""
    prefix = "l" if is_link else ("d" if is_dir else "-")
    perms = []
    shifts = [6, 3, 0]
    for shift in shifts:
        val = (mode >> shift) & 0o7
        r = "r" if val & 4 else "-"
        w = "w" if val & 2 else "-"
        x = "x" if val & 1 else "-"
        perms.append(f"{r}{w}{x}")
    return prefix + "".join(perms)


def _parse_numeric_mode(mode_val: int | str) -> int:
    """Parse octal mode representation into an integer."""
    if isinstance(mode_val, int):
        return mode_val
    mode_str = str(mode_val).strip()
    if mode_str.isdigit():
        return int(mode_str, 8)
    raise ValueError(f"Invalid mode: {mode_val}")


class VirtualFilesystem:
    """Thread-safe virtual filesystem simulating a standard Ubuntu Linux environment."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        now = time.time()

        # A dictionary mapping absolute paths of files to their content (bytes)
        # and directories to True.
        self.fs: Dict[str, Any] = {
            "/": True,
            "/bin": True,
            "/boot": True,
            "/dev": True,
            "/etc": True,
            "/etc/cron.d": True,
            "/etc/cron.daily": True,
            "/etc/cron.hourly": True,
            "/etc/cron.monthly": True,
            "/etc/cron.weekly": True,
            "/etc/default": True,
            "/etc/netplan": True,
            "/etc/network": True,
            "/etc/nginx": True,
            "/etc/security": True,
            "/etc/ssh": True,
            "/etc/ssl": True,
            "/home": True,
            "/home/ubuntu": True,
            "/media": True,
            "/mnt": True,
            "/opt": True,
            "/proc": True,
            "/root": True,
            "/root/.ssh": True,
            "/root/scripts": True,
            "/run": True,
            "/sbin": True,
            "/srv": True,
            "/sys": True,
            "/sys/class": True,
            "/sys/class/net": True,
            "/sys/class/net/eth0": True,
            "/tmp": True,
            "/usr": True,
            "/usr/bin": True,
            "/usr/include": True,
            "/usr/lib": True,
            "/usr/local": True,
            "/usr/local/bin": True,
            "/usr/local/sbin": True,
            "/usr/sbin": True,
            "/var": True,
            "/var/backups": True,
            "/var/cache": True,
            "/var/lib": True,
            "/var/log": True,
            "/var/log/nginx": True,
            "/var/mail": True,
            "/var/run": True,
            "/var/spool": True,
            "/var/spool/cron": True,
            "/var/spool/cron/crontabs": True,
            "/var/tmp": True,
            "/var/www": True,
            "/var/www/html": True,

            # --- /root files (juicy decoys for attackers) ---
            "/root/.bash_history": (
                b"ls -la\n"
                b"cat /etc/passwd\n"
                b"cd /var/www/html\n"
                b"mysql -u root -p\n"
                b"mysqldump -u root -p wordpress > /root/wordpress_backup.sql\n"
                b"tar czf backups.tar.gz /var/www/html\n"
                b"scp backups.tar.gz deploy@10.0.0.5:/backups/\n"
                b"nano /etc/nginx/nginx.conf\n"
                b"systemctl restart nginx\n"
                b"python3 manage.py migrate\n"
                b"python3 manage.py collectstatic\n"
                b"exit\n"
            ),
            "/root/.bashrc": (
                b"# ~/.bashrc\n"
                b"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                b"alias ll='ls -alF'\n"
                b"alias la='ls -A'\n"
                b"alias l='ls -CF'\n"
                b"export EDITOR=nano\n"
                b"export HISTSIZE=10000\n"
                b"export DB_PASS='prod_db_pass_92837'\n"
                b"export REDIS_URL='redis://localhost:6379/0'\n"
                b"PS1='\\u@\\h:\\w\\$ '\n"
            ),
            "/root/.profile": b"# ~/.profile: executed by Bourne-compatible login shells.\nif [ \"$BASH\" ]; then\n  if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\n  fi\nfi\nmesg n 2> /dev/null || true\n",
            "/root/.ssh/authorized_keys": (
                b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5fakeKey0000LongBase64EncodedRSAKeyHereXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX deploy@bastion\n"
                b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeEd25519KeyHerePlaceholderXXXXXXXXXXXXXXXXXX admin@laptop\n"
            ),
            "/root/backups.tar.gz": b"\x1f\x8b\x08\x00fake tarball data content here",
            "/root/database.sql": (
                b"-- MySQL dump 10.13 Distrib 8.0.33, for Linux (x86_64)\n"
                b"-- Host: localhost    Database: wordpress\n"
                b"-- Server version: 8.0.33\n\n"
                b"CREATE TABLE `users` (\n"
                b"  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n"
                b"  `user_login` varchar(60) NOT NULL DEFAULT '',\n"
                b"  `user_pass` varchar(255) NOT NULL DEFAULT '',\n"
                b"  `user_email` varchar(100) NOT NULL DEFAULT '',\n"
                b"  PRIMARY KEY (`ID`)\n"
                b") ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4;\n\n"
                b"INSERT INTO `users` VALUES\n"
                b"(1,'admin','$P$BnlqdFakeHash0001XXXXXXXXXXXXX','admin@example.com'),\n"
                b"(2,'editor','$P$BnlqdFakeHash0002XXXXXXXXXXXXX','editor@example.com'),\n"
                b"(3,'johndoe','$P$BnlqdFakeHash0003XXXXXXXXXXXXX','john@example.com');\n"
            ),
            "/root/deploy.sh": (
                b"#!/bin/bash\n"
                b"set -e\n"
                b"echo '[deploy] Pulling latest code...'\n"
                b"git -C /var/www/html pull origin main\n"
                b"echo '[deploy] Installing dependencies...'\n"
                b"pip install -r /var/www/html/requirements.txt -q\n"
                b"echo '[deploy] Running database migrations...'\n"
                b"python3 /var/www/html/manage.py migrate --noinput\n"
                b"echo '[deploy] Collecting static assets...'\n"
                b"python3 /var/www/html/manage.py collectstatic --noinput\n"
                b"echo '[deploy] Restarting application...'\n"
                b"systemctl restart gunicorn nginx\n"
                b"echo '[deploy] Deploy successful!'\n"
            ),
            "/root/secrets.txt": (
                b"# Production Credentials - DO NOT COMMIT\n"
                b"AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID_12345678\n"
                b"AWS_SECRET_ACCESS_KEY=mock_aws_secret_access_key_987654321\n"
                b"STRIPE_API_KEY=stripe_test_placeholder_998877\n"
                b"SENDGRID_API_KEY=SG.mock_sendgrid_key_placeholder\n"
                b"DB_ROOT_PASSWORD=prod_mysql_root_pass_19283\n"
            ),

            # --- /home/ubuntu files ---
            "/home/ubuntu/.bash_history": b"sudo su -\ncd /var/www/html\ngit status\n",
            "/home/ubuntu/.bashrc": (
                b"# ~/.bashrc for ubuntu user\n"
                b"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                b"PS1='\\u@\\h:\\w\\$ '\n"
            ),
            "/home/ubuntu/.ssh": True,
            "/home/ubuntu/.ssh/authorized_keys": (
                b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5fakeKeyUbuntuUserPlaceholderXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ubuntu@workstation\n"
            ),

            # --- /etc files ---
            "/etc/crontab": (
                b"SHELL=/bin/sh\n"
                b"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                b"# m h dom mon dow user command\n"
                b"17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
                b"25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                b"*/5 *   * * *   root    /root/scripts/health_check.sh >> /var/log/health.log 2>&1\n"
                b"0 2     * * *   root    mysqldump -u root -pPROD_DB_PASS_FAKE wordpress > /root/db_backup.sql\n"
            ),
            "/etc/environment": b'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"\n',
            "/etc/group": (
                b"root:x:0:\n"
                b"daemon:x:1:\n"
                b"bin:x:2:\n"
                b"sys:x:3:\n"
                b"adm:x:4:ubuntu\n"
                b"sudo:x:27:ubuntu,deploy\n"
                b"www-data:x:33:\n"
                b"docker:x:999:ubuntu\n"
                b"ubuntu:x:1000:\n"
                b"deploy:x:1001:\n"
            ),
            "/etc/hostname": b"web-prod-01\n",
            "/etc/hosts": (
                b"127.0.0.1\tlocalhost\n"
                b"127.0.1.1\tweb-prod-01\n"
                b"10.0.0.1\tbastion bastion.internal\n"
                b"10.0.0.5\tdeploy deploy.internal\n"
                b"10.0.0.10\tdb-primary db-primary.internal\n"
                b"10.0.0.11\tdb-replica db-replica.internal\n"
                b"10.0.0.20\tcache cache.internal redis.internal\n\n"
                b"# The following lines are desirable for IPv6 capable hosts\n"
                b"::1\tip6-localhost ip6-loopback\n"
            ),
            "/etc/issue": b"Ubuntu 22.04.4 LTS \\n \\l\n\n",
            "/etc/os-release": (
                b'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                b'NAME="Ubuntu"\n'
                b'VERSION_ID="22.04"\n'
                b'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                b'VERSION_CODENAME=jammy\n'
                b'ID=ubuntu\n'
                b'ID_LIKE=debian\n'
                b'HOME_URL="https://www.ubuntu.com/"\n'
                b'SUPPORT_URL="https://help.ubuntu.com/"\n'
                b'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
                b'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
                b'UBUNTU_CODENAME=jammy\n'
            ),
            "/etc/lsb-release": (
                b"DISTRIB_ID=Ubuntu\n"
                b"DISTRIB_RELEASE=22.04\n"
                b"DISTRIB_CODENAME=jammy\n"
                b"DISTRIB_DESCRIPTION=\"Ubuntu 22.04.4 LTS\"\n"
            ),
            "/etc/passwd": (
                b"root:x:0:0:root:/root:/bin/bash\n"
                b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                b"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                b"deploy:x:1001:1001:Deploy User:/home/ubuntu:/bin/bash\n"
                b"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            ),
            "/etc/shadow": (
                b"root:$6$fakeSalt0001$FakeHashedPasswordRoot0001XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
                b"ubuntu:$6$fakeSalt0002$FakeHashedPasswordUbuntu002XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
                b"deploy:$6$fakeSalt0003$FakeHashedPasswordDeploy003XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
            ),
            "/etc/shells": (
                b"# /etc/shells: valid login shells\n"
                b"/bin/sh\n"
                b"/bin/bash\n"
                b"/usr/bin/sh\n"
                b"/usr/bin/bash\n"
                b"/bin/rbash\n"
                b"/usr/bin/rbash\n"
                b"/bin/dash\n"
                b"/usr/bin/dash\n"
            ),
            "/etc/sudoers": (
                b"# /etc/sudoers\n"
                b"Defaults\tenv_reset\n"
                b"Defaults\tmail_badpass\n"
                b"Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
                b"root\tALL=(ALL:ALL) ALL\n"
                b"%admin ALL=(ALL) ALL\n"
                b"%sudo\tALL=(ALL:ALL) ALL\n"
                b"www-data ALL=(ALL) NOPASSWD: /usr/sbin/service nginx restart\n"
            ),
            "/etc/fstab": (
                b"# /etc/fstab: static file system information.\n"
                b"UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 /               ext4    errors=remount-ro 0       1\n"
                b"UUID=f9e8d7c6-b5a4-3210-9876-543210fedcba /data           ext4    defaults        0       2\n"
            ),
            "/etc/resolv.conf": b"nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch internal\n",
            "/etc/network/interfaces": b"# interfaces(5) file used by ifup(8) and ifdown(8)\nauto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n  address 10.0.0.3\n  netmask 255.255.255.0\n  gateway 10.0.0.1\n",
            "/etc/netplan/01-netcfg.yaml": b"network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      addresses:\n        - 10.0.0.3/24\n      gateway4: 10.0.0.1\n      nameservers:\n        addresses: [8.8.8.8, 1.1.1.1]\n",
            "/etc/security/limits.conf": b"# /etc/security/limits.conf\n*               soft    nofile          65535\n*               hard    nofile          65535\nroot            soft    nofile          65535\nroot            hard    nofile          65535\n",
            "/etc/ssh/sshd_config": (
                b"# Package generated configuration file\n"
                b"# See the sshd_config(5) manpage for details\n"
                b"Port 22\n"
                b"Protocol 2\n"
                b"HostKey /etc/ssh/ssh_host_rsa_key\n"
                b"HostKey /etc/ssh/ssh_host_ecdsa_key\n"
                b"HostKey /etc/ssh/ssh_host_ed25519_key\n"
                b"PermitRootLogin yes\n"
                b"PasswordAuthentication yes\n"
                b"PubkeyAuthentication yes\n"
                b"AuthorizedKeysFile .ssh/authorized_keys\n"
                b"ChallengeResponseAuthentication no\n"
                b"UsePAM yes\n"
                b"X11Forwarding yes\n"
                b"PrintMotd no\n"
                b"AcceptEnv LANG LC_*\n"
                b"Subsystem sftp /usr/lib/openssh/sftp-server\n"
            ),
            "/etc/nginx/nginx.conf": (
                b"user www-data;\n"
                b"worker_processes auto;\n"
                b"error_log /var/log/nginx/error.log warn;\n"
                b"events { worker_connections 1024; }\n"
                b"http {\n"
                b"    include /etc/nginx/mime.types;\n"
                b"    server {\n"
                b"        listen 80;\n"
                b"        server_name example.com www.example.com;\n"
                b"        root /var/www/html;\n"
                b"        location / { try_files $uri $uri/ /index.php?$query_string; }\n"
                b"        location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.1-fpm.sock; }\n"
                b"    }\n"
                b"}\n"
            ),

            # --- /var/www/html files ---
            "/var/www/html/index.php": b"<?php phpinfo(); ?>",
            "/var/www/html/wp-config.php": (
                b"<?php\n"
                b"/** WordPress DB Config */\n"
                b"define('DB_NAME', 'wordpress');\n"
                b"define('DB_USER', 'wp_user');\n"
                b"define('DB_PASSWORD', 'super_secure_wp_pass_129381');\n"
                b"define('DB_HOST', '10.0.0.10');\n"
                b"define('DB_CHARSET', 'utf8mb4');\n"
                b"define('AUTH_KEY', 'put your unique phrase here');\n"
                b"define('SECURE_AUTH_KEY', 'put your unique phrase here');\n"
                b"define('LOGGED_IN_KEY', 'put your unique phrase here');\n"
                b"define('NONCE_KEY', 'put your unique phrase here');\n"
                b"$table_prefix = 'wp_';\n"
                b"define('WP_DEBUG', false);\n"
                b"if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\n"
                b"require_once ABSPATH . 'wp-settings.php';\n"
            ),
            "/var/www/html/.env": (
                b"APP_NAME=ProductionApp\n"
                b"APP_ENV=production\n"
                b"APP_KEY=base64:FakeAppKeyPlaceholderXXXXXXXXXXXXXXXX=\n"
                b"APP_DEBUG=false\n"
                b"APP_URL=https://example.com\n\n"
                b"DB_CONNECTION=mysql\n"
                b"DB_HOST=10.0.0.10\n"
                b"DB_PORT=3306\n"
                b"DB_DATABASE=production\n"
                b"DB_USERNAME=app_user\n"
                b"DB_PASSWORD=prod_db_pass_92837\n\n"
                b"REDIS_HOST=10.0.0.20\n"
                b"REDIS_PASSWORD=null\n"
                b"REDIS_PORT=6379\n\n"
                b"MAIL_DRIVER=smtp\n"
                b"MAIL_HOST=smtp.sendgrid.net\n"
                b"MAIL_PORT=587\n"
                b"MAIL_USERNAME=apikey\n"
                b"MAIL_PASSWORD=SG.mock_sendgrid_key_placeholder\n"
            ),
            "/var/www/html/config.php": (
                b"<?php\n"
                b"$config = array(\n"
                b"    'db_host' => '10.0.0.10',\n"
                b"    'db_user' => 'app_user',\n"
                b"    'db_pass' => 'prod_db_pass_92837',\n"
                b"    'db_name' => 'production',\n"
                b"    'api_key' => 'sk_live_fake_key_abc123xyz',\n"
                b");\n"
            ),
            "/var/www/html/database.php": (
                b"<?php\n"
                b"$mysqli = new mysqli('10.0.0.10', 'app_user', 'prod_db_pass_92837', 'production');\n"
            ),
            "/var/www/html/backup.sql": (
                b"-- Database backup\n"
                b"INSERT INTO users (username, password) VALUES ('admin', 'hashed_password_123');\n"
            ),
            "/var/www/html/requirements.txt": (
                b"fastapi==0.115.12\n"
                b"uvicorn==0.34.0\n"
                b"sqlalchemy==2.0.0\n"
                b"redis==5.0.0\n"
            ),
            "/var/www/html/docker-compose.yml": (
                b"version: '3.8'\n"
                b"services:\n"
                b"  web:\n"
                b"    image: nginx:latest\n"
                b"    ports:\n"
                b"      - '80:80'\n"
                b"  db:\n"
                b"    image: mysql:8.0\n"
                b"    environment:\n"
                b"      MYSQL_ROOT_PASSWORD: prod_mysql_root_pass_19283\n"
            ),

            # --- /var/log files ---
            "/var/log/auth.log": (
                b"Jun 28 07:14:01 web-prod-01 sshd[1234]: Accepted password for root from 192.168.1.1 port 54321 ssh2\n"
                b"Jun 28 08:23:17 web-prod-01 sshd[1235]: Failed password for root from 203.0.113.5 port 12345 ssh2\n"
                b"Jun 28 09:01:55 web-prod-01 sshd[1236]: Invalid user admin from 198.51.100.7 port 43210\n"
                b"Jun 28 10:45:02 web-prod-01 sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash\n"
                b"Jun 28 11:12:33 web-prod-01 sshd[1240]: Accepted publickey for deploy from 10.0.0.1 port 32100 ssh2\n"
            ),
            "/var/log/syslog": (
                b"Jun 28 06:25:01 web-prod-01 CRON[1200]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))\n"
                b"Jun 28 07:00:01 web-prod-01 systemd[1]: Starting Daily apt download activities...\n"
                b"Jun 28 07:00:03 web-prod-01 systemd[1]: apt-daily.service: Deactivated successfully.\n"
            ),
            "/var/log/messages": b"Jun 28 06:00:01 web-prod-01 kernel: [    0.000000] Linux version 5.15.0-94-generic (buildd@lcy02-amd64-032)\n",
            "/var/log/wtmp": b"\x00" * 384,
            "/var/log/lastlog": b"\x00" * 292,
            "/var/log/nginx/access.log": (
                b'203.0.113.5 - - [28/Jun/2026:07:14:01 +0000] "GET /wp-admin HTTP/1.1" 302 0 "-" "Mozilla/5.0"\n'
                b'198.51.100.7 - - [28/Jun/2026:07:15:22 +0000] "POST /wp-login.php HTTP/1.1" 200 3456 "-" "curl/7.88"\n'
                b'10.0.0.1 - - [28/Jun/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 12043 "-" "internal-monitor/1.0"\n'
                b'203.0.113.10 - - [28/Jun/2026:09:23:45 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "python-requests/2.28"\n'
            ),
            "/var/log/nginx/error.log": (
                b"2026/06/28 07:15:22 [error] 12345#12345: *1 FastCGI sent in stderr: \"PHP message: PHP Warning: ...\"\n"
                b"2026/06/28 09:23:45 [error] 12345#12345: *14 open() \"/var/www/html/phpmyadmin\" failed (2: No such file)\n"
            ),

            # --- /proc (lightweight simulation) ---
            "/proc/version": b"Linux version 5.15.0-94-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #104-Ubuntu SMP x86_64\n",
            "/proc/meminfo": (
                b"MemTotal:        4026256 kB\n"
                b"MemFree:          814320 kB\n"
                b"MemAvailable:    2159504 kB\n"
                b"Buffers:          128452 kB\n"
                b"Cached:          1420204 kB\n"
                b"SwapTotal:       2097148 kB\n"
                b"SwapFree:        2097148 kB\n"
            ),
            "/proc/cpuinfo": (
                b"processor\t: 0\n"
                b"vendor_id\t: GenuineIntel\n"
                b"model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
                b"cpu MHz\t\t: 2400.058\n"
                b"cache size\t: 30720 KB\n"
                b"cpu cores\t: 2\n"
                b"processor\t: 1\n"
                b"vendor_id\t: GenuineIntel\n"
                b"model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
                b"cpu cores\t: 2\n"
            ),
            "/proc/uptime": b"432100.55 864200.11\n",
            "/proc/loadavg": b"0.08 0.12 0.09 1/127 12345\n",
            "/proc/mounts": (
                b"/dev/root / ext4 rw,relatime,errors=remount-ro 0 0\n"
                b"devtmpfs /dev devtmpfs rw,nosuid,size=2000000k,nr_inodes=500000,mode=755 0 0\n"
                b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
                b"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
                b"/dev/sdb1 /data ext4 rw,relatime 0 0\n"
            ),
            "/proc/net/tcp": (
                b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                b"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
                b"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 12346 1 0000000000000000 100 0 0 10 0\n"
                b"   2: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n"
            ),
            "/proc/net/route": (
                b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                b"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                b"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
            ),
            "/proc/cmdline": b"BOOT_IMAGE=/boot/vmlinuz-5.15.0-94-generic root=UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 ro quiet splash\n",

            # --- /dev simulation ---
            "/dev/null": b"",
            "/dev/zero": b"\x00" * 1024,
            "/dev/urandom": b"\x4a\x9f\x12\x8e\xbb\x03\xcc\xdd" * 64,

            # --- /sys simulation ---
            "/sys/class/net/eth0/address": b"02:42:0a:00:00:03\n",

            # --- Standard system binaries stubs (so ls /bin, which, stat /bin/sh works) ---
            "/bin/sh": b"#!/bin/sh\n# system binary stub\n",
            "/bin/bash": b"#!/bin/bash\n# system binary stub\n",
            "/bin/ls": b"# ELF binary\n",
            "/bin/cat": b"# ELF binary\n",
            "/bin/echo": b"# ELF binary\n",
            "/bin/grep": b"# ELF binary\n",
            "/bin/chmod": b"# ELF binary\n",
            "/bin/chown": b"# ELF binary\n",
            "/bin/cp": b"# ELF binary\n",
            "/bin/mv": b"# ELF binary\n",
            "/bin/rm": b"# ELF binary\n",
            "/bin/mkdir": b"# ELF binary\n",
            "/bin/ps": b"# ELF binary\n",
            "/bin/uname": b"# ELF binary\n",
            "/bin/kill": b"# ELF binary\n",
            "/bin/tar": b"# ELF binary\n",
            "/bin/netstat": b"# ELF binary\n",
            "/usr/bin/curl": b"# ELF binary\n",
            "/usr/bin/wget": b"# ELF binary\n",
            "/usr/bin/python3": b"# ELF binary\n",
            "/usr/bin/sudo": b"# SUID binary\n",
            "/usr/bin/su": b"# SUID binary\n",
            "/usr/bin/nc": b"# ELF binary\n",
            "/usr/bin/git": b"# ELF binary\n",
            "/usr/bin/ssh": b"# ELF binary\n",
            "/usr/bin/scp": b"# ELF binary\n",
            "/usr/bin/head": b"# ELF binary\n",
            "/usr/bin/tail": b"# ELF binary\n",
            "/usr/bin/wc": b"# ELF binary\n",
            "/usr/bin/find": b"# ELF binary\n",
            "/usr/bin/awk": b"# ELF binary\n",
            "/usr/bin/sed": b"# ELF binary\n",
        }

        # Initialize POSIX metadata for every entry in self.fs
        self._metadata: Dict[str, Dict[str, Any]] = {}
        for path, val in self.fs.items():
            is_d = val is True
            # Defaults based on path
            if is_d:
                mode = 0o755
            elif path.startswith("/root/.ssh") or path == "/etc/shadow" or path == "/root/secrets.txt":
                mode = 0o600
            elif path.endswith(".sh") or path.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")):
                mode = 0o755
            else:
                mode = 0o644

            owner = "root"
            group = "root"
            uid = 0
            gid = 0
            if path.startswith("/var/www"):
                owner = "www-data"
                group = "www-data"
                uid = 33
                gid = 33
            elif path.startswith("/home/ubuntu"):
                owner = "ubuntu"
                group = "ubuntu"
                uid = 1000
                gid = 1000

            self._metadata[path] = {
                "mode": mode,
                "owner": owner,
                "group": group,
                "uid": uid,
                "gid": gid,
                "mtime": now - 3600,
                "atime": now - 60,
                "ctime": now - 3600,
                "is_symlink": False,
                "target": None,
            }

        # Setup standard symlinks
        self.symlink("/bin/bash", "/bin/rbash")
        self.symlink("/usr/bin/python3", "/usr/bin/python")

    def _normalize_path(self, cwd: str, path: str) -> str:
        """Resolve a path relative to cwd, handling dots, double dots, and ensuring virtual root jail."""
        if not path:
            return cwd
        if path.startswith("/"):
            parts = path.split("/")
        else:
            parts = (cwd.split("/") if cwd != "/" else []) + path.split("/")

        stack: List[str] = []
        for p in parts:
            if not p or p == ".":
                continue
            if p == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(p)
        return "/" + "/".join(stack)

    def resolve_path(self, path: str, cwd: str = "/") -> str:
        """Fully resolve a path following symbolic links up to 10 hops."""
        with self._lock:
            cur = self._normalize_path(cwd, path)
            visited = set()
            for _ in range(10):
                if cur in visited:
                    break  # loop detected
                visited.add(cur)
                meta = self._metadata.get(cur)
                if meta and meta.get("is_symlink") and meta.get("target"):
                    target = meta["target"]
                    parent = "/".join(cur.split("/")[:-1]) or "/"
                    cur = self._normalize_path(parent, target)
                else:
                    break
            return cur

    def exists(self, path: str) -> bool:
        with self._lock:
            return path in self.fs

    def is_dir(self, path: str) -> bool:
        with self._lock:
            return self.fs.get(path) is True

    def is_file(self, path: str) -> bool:
        with self._lock:
            return isinstance(self.fs.get(path), bytes)

    def is_symlink(self, path: str) -> bool:
        with self._lock:
            meta = self._metadata.get(path)
            return bool(meta and meta.get("is_symlink"))

    def readlink(self, path: str) -> Optional[str]:
        with self._lock:
            meta = self._metadata.get(path)
            if meta and meta.get("is_symlink"):
                return meta.get("target")
            return None

    def symlink(self, target: str, link_path: str) -> bool:
        """Create a symbolic link at link_path pointing to target."""
        with self._lock:
            parent = "/".join(link_path.split("/")[:-1]) or "/"
            if not self.is_dir(parent):
                return False
            if link_path in self.fs:
                return False
            # Store link in fs as 0-byte or link indicator
            self.fs[link_path] = b""
            now = time.time()
            self._metadata[link_path] = {
                "mode": 0o777,
                "owner": "root",
                "group": "root",
                "uid": 0,
                "gid": 0,
                "mtime": now,
                "atime": now,
                "ctime": now,
                "is_symlink": True,
                "target": target,
            }
            return True

    def list_dir(self, path: str) -> List[str] | None:
        with self._lock:
            resolved = self.resolve_path(path)
            if not self.is_dir(resolved):
                return None
            prefix = resolved if resolved.endswith("/") else resolved + "/"
            res = []
            for k in self.fs.keys():
                if k == resolved:
                    continue
                if k.startswith(prefix):
                    sub = k[len(prefix):]
                    item = sub.split("/")[0]
                    if item not in res:
                        res.append(item)
            return sorted(res)

    def read_file(self, path: str) -> bytes | None:
        with self._lock:
            resolved = self.resolve_path(path)
            if self.is_file(resolved):
                meta = self._metadata.get(resolved)
                if meta:
                    meta["atime"] = time.time()
                return self.fs[resolved]
            return None

    def stat(self, path: str) -> dict[str, Any] | None:
        """Return comprehensive POSIX-like metadata for a virtual path."""
        with self._lock:
            if path not in self.fs:
                return None
            is_dir = self.is_dir(path)
            meta = self._metadata.get(path, {})
            is_link = meta.get("is_symlink", False)
            mode_num = meta.get("mode", 0o755 if is_dir else 0o644)
            size = 4096 if is_dir else len(self.fs.get(path) or b"")
            mode_str = _mode_to_str(mode_num, is_dir, is_link)

            return {
                "path": path,
                "name": path.rstrip("/").split("/")[-1] or "/",
                "type": "symlink" if is_link else ("directory" if is_dir else "file"),
                "size": size,
                "mode": mode_str,
                "mode_octal": oct(mode_num),
                "owner": meta.get("owner", "root"),
                "group": meta.get("group", "root"),
                "uid": meta.get("uid", 0),
                "gid": meta.get("gid", 0),
                "mtime": meta.get("mtime", time.time()),
                "atime": meta.get("atime", time.time()),
                "ctime": meta.get("ctime", time.time()),
            }

    def chmod(self, path: str, mode: int | str) -> bool:
        """Change permissions of a file or directory. Supports octal int or string, or symbolic modes."""
        with self._lock:
            if path not in self.fs:
                return False
            meta = self._metadata.setdefault(path, {})
            current_mode = meta.get("mode", 0o755 if self.is_dir(path) else 0o644)

            # Symbolic mode support (+x, -w, u+x, a+r, etc.)
            if isinstance(mode, str) and not mode.isdigit():
                mode_str = mode.strip()
                new_mode = current_mode
                for part in mode_str.split(","):
                    part = part.strip()
                    m = re.match(r"^([ugoa]*)([\+\-\=])([rwxXst]+)$", part)
                    if not m:
                        continue
                    who, op, perms = m.groups()
                    mask = 0
                    if "r" in perms:
                        mask |= 0o444 if not who or "a" in who else (0o400 if "u" in who else 0) | (0o040 if "g" in who else 0) | (0o004 if "o" in who else 0)
                    if "w" in perms:
                        mask |= 0o222 if not who or "a" in who else (0o200 if "u" in who else 0) | (0o020 if "g" in who else 0) | (0o002 if "o" in who else 0)
                    if "x" in perms or "X" in perms:
                        mask |= 0o111 if not who or "a" in who else (0o100 if "u" in who else 0) | (0o010 if "g" in who else 0) | (0o001 if "o" in who else 0)

                    if op == "+":
                        new_mode |= mask
                    elif op == "-":
                        new_mode &= ~mask
                    elif op == "=":
                        clear_mask = 0o777 if not who or "a" in who else (0o700 if "u" in who else 0) | (0o070 if "g" in who else 0) | (0o007 if "o" in who else 0)
                        new_mode = (new_mode & ~clear_mask) | mask
                meta["mode"] = new_mode
                meta["ctime"] = time.time()
                return True

            try:
                numeric_mode = _parse_numeric_mode(mode)
                meta["mode"] = numeric_mode
                meta["ctime"] = time.time()
                return True
            except ValueError:
                return False

    def chown(self, path: str, user: str | int, group: str | int | None = None) -> bool:
        """Change owner and optionally group of a file or directory."""
        with self._lock:
            if path not in self.fs:
                return False
            meta = self._metadata.setdefault(path, {})
            if isinstance(user, int):
                meta["uid"] = user
                meta["owner"] = "root" if user == 0 else f"user{user}"
            else:
                meta["owner"] = str(user)
                meta["uid"] = 0 if user == "root" else 1000

            if group is not None:
                if isinstance(group, int):
                    meta["gid"] = group
                    meta["group"] = "root" if group == 0 else f"group{group}"
                else:
                    meta["group"] = str(group)
                    meta["gid"] = 0 if group == "root" else 1000

            meta["ctime"] = time.time()
            return True

    def touch(self, path: str) -> bool:
        """Update file timestamp or create empty file if not existing."""
        with self._lock:
            now = time.time()
            if path in self.fs:
                meta = self._metadata.setdefault(path, {})
                meta["mtime"] = now
                meta["atime"] = now
                return True
            return self.write_file(path, b"")

    def append_file(self, path: str, content: bytes) -> bool:
        """Append bytes to an existing file, or create it if missing."""
        with self._lock:
            if path in self.fs and self.is_file(path):
                existing = self.fs[path]
                if len(existing) + len(content) > MAX_FILE_SIZE:
                    return False
                self.fs[path] = existing + content
                meta = self._metadata.setdefault(path, {})
                now = time.time()
                meta["mtime"] = now
                meta["atime"] = now
                return True
            return self.write_file(path, content)

    def truncate(self, path: str, size: int = 0) -> bool:
        """Truncate a file to a specified length."""
        with self._lock:
            if not self.is_file(path):
                return False
            data = self.fs[path]
            if size < len(data):
                self.fs[path] = data[:size]
            else:
                self.fs[path] = data + b"\x00" * (size - len(data))
            meta = self._metadata.setdefault(path, {})
            meta["mtime"] = time.time()
            return True

    def copy(self, source: str, destination: str) -> bool:
        """Copy a file inside the virtual filesystem."""
        with self._lock:
            if not self.is_file(source) or self.is_dir(destination):
                return False
            content = self.read_file(source)
            if content is None:
                return False
            success = self.write_file(destination, content)
            if success and source in self._metadata:
                src_meta = dict(self._metadata[source])
                src_meta["ctime"] = time.time()
                src_meta["atime"] = time.time()
                src_meta["mtime"] = time.time()
                self._metadata[destination] = src_meta
            return success

    def move(self, source: str, destination: str) -> bool:
        """Move or rename a file or empty directory inside the virtual filesystem."""
        with self._lock:
            if source == "/" or source not in self.fs or destination in self.fs:
                return False
            parent = "/".join(destination.split("/")[:-1]) or "/"
            if not self.is_dir(parent):
                return False
            if self.is_file(source):
                self.fs[destination] = self.fs.pop(source)
                if source in self._metadata:
                    self._metadata[destination] = self._metadata.pop(source)
                return True
            if self.is_dir(source):
                prefix = source if source.endswith("/") else source + "/"
                children = [k for k in self.fs if k != source and k.startswith(prefix)]
                if children:
                    return False
                self.fs[destination] = self.fs.pop(source)
                if source in self._metadata:
                    self._metadata[destination] = self._metadata.pop(source)
                return True
            return False

    def write_file(self, path: str, content: bytes) -> bool:
        with self._lock:
            if len(content) > MAX_FILE_SIZE:
                return False
            parent = "/".join(path.split("/")[:-1])
            if not parent:
                parent = "/"
            if not self.is_dir(parent):
                return False
            if self.is_dir(path):
                return False

            now = time.time()
            self.fs[path] = content
            self._metadata[path] = {
                "mode": 0o644,
                "owner": "root",
                "group": "root",
                "uid": 0,
                "gid": 0,
                "mtime": now,
                "atime": now,
                "ctime": now,
                "is_symlink": False,
                "target": None,
            }
            return True

    def mkdir(self, path: str) -> bool:
        with self._lock:
            parent = "/".join(path.split("/")[:-1])
            if not parent:
                parent = "/"
            if not self.is_dir(parent):
                return False
            if path in self.fs:
                return False

            now = time.time()
            self.fs[path] = True
            self._metadata[path] = {
                "mode": 0o755,
                "owner": "root",
                "group": "root",
                "uid": 0,
                "gid": 0,
                "mtime": now,
                "atime": now,
                "ctime": now,
                "is_symlink": False,
                "target": None,
            }
            return True

    def rm(self, path: str) -> bool:
        with self._lock:
            if self.is_file(path):
                del self.fs[path]
                self._metadata.pop(path, None)
                return True
            return False

    def rmdir(self, path: str) -> bool:
        with self._lock:
            if self.is_dir(path):
                prefix = path if path.endswith("/") else path + "/"
                for k in self.fs.keys():
                    if k != path and k.startswith(prefix):
                        return False
                del self.fs[path]
                self._metadata.pop(path, None)
                return True
            return False

    def grep(self, pattern: str, path: str) -> list[str]:
        """Simple grep: return lines containing pattern in a file."""
        with self._lock:
            content = self.read_file(path)
            if content is None:
                return []
            lines = content.decode("utf-8", errors="replace").splitlines()
            return [line for line in lines if pattern.lower() in line.lower()]

    def find(self, root: str, name_pattern: str | None = None) -> list[str]:
        """Return all paths under root, optionally filtered by name pattern (supports wildcards)."""
        with self._lock:
            prefix = root if root.endswith("/") else root + "/"
            results = []
            for k in self.fs:
                if k == root or k.startswith(prefix):
                    base = k.split("/")[-1]
                    if name_pattern is None:
                        results.append(k)
                    elif any(c in name_pattern for c in "*?[]"):
                        if fnmatch.fnmatch(base, name_pattern):
                            results.append(k)
                    elif name_pattern in base:
                        results.append(k)
            return sorted(results)

    def head(self, path: str, lines: int = 10) -> list[str]:
        """Return the first `lines` lines of a file."""
        with self._lock:
            content = self.read_file(path)
            if content is None:
                return []
            all_lines = content.decode("utf-8", errors="replace").splitlines()
            return all_lines[:lines]

    def tail(self, path: str, lines: int = 10) -> list[str]:
        """Return the last `lines` lines of a file."""
        with self._lock:
            content = self.read_file(path)
            if content is None:
                return []
            all_lines = content.decode("utf-8", errors="replace").splitlines()
            return all_lines[-lines:] if lines > 0 else []

    def wc(self, path: str) -> dict[str, int]:
        """Return line, word, and byte counts for a file (like the POSIX wc utility)."""
        with self._lock:
            content = self.read_file(path)
            if content is None:
                return {"lines": 0, "words": 0, "bytes": 0}
            lines = content.count(b"\n")
            text = content.decode("utf-8", errors="replace")
            words = len(text.split())
            return {"lines": lines, "words": words, "bytes": len(content)}

    def checksum(self, path: str, algo: str = "sha256") -> Optional[str]:
        """Compute cryptographic hash of a file."""
        with self._lock:
            content = self.read_file(path)
            if content is None:
                return None
            algo_lower = algo.lower().replace("-", "")
            if algo_lower in ("md5", "md5sum"):
                return hashlib.md5(content).hexdigest()
            elif algo_lower in ("sha1", "sha1sum"):
                return hashlib.sha1(content).hexdigest()
            else:
                return hashlib.sha256(content).hexdigest()

    def diff(self, path1: str, path2: str) -> list[str]:
        """Compute a unified diff between two files."""
        with self._lock:
            c1 = self.read_file(path1)
            c2 = self.read_file(path2)
            if c1 is None or c2 is None:
                return []
            l1 = c1.decode("utf-8", errors="replace").splitlines(keepends=True)
            l2 = c2.decode("utf-8", errors="replace").splitlines(keepends=True)
            return list(difflib.unified_diff(l1, l2, fromfile=path1, tofile=path2))

    def disk_usage(self, path: str = "/") -> dict[str, int]:
        """Return simulated disk usage statistics (total, used, free bytes)."""
        with self._lock:
            used = sum(len(v) for v in self.fs.values() if isinstance(v, bytes))
            total = 20 * 1024 * 1024 * 1024  # 20 GB simulated
            free = max(0, total - used)
            return {"total": total, "used": used, "free": free}

    def tree(self, root: str = "/", max_depth: int = 3) -> str:
        """Generate a visual ASCII tree representation of the filesystem structure."""
        with self._lock:
            if not self.is_dir(root):
                return f"{root} [error opening dir]"

            lines = [root]

            def _build(cur: str, prefix: str, depth: int):
                if depth > max_depth:
                    return
                items = self.list_dir(cur)
                if not items:
                    return
                count = len(items)
                for idx, item in enumerate(items):
                    is_last = idx == count - 1
                    connector = "└── " if is_last else "├── "
                    subpath = f"{cur.rstrip('/')}/{item}"
                    lines.append(f"{prefix}{connector}{item}")
                    if self.is_dir(subpath):
                        new_prefix = prefix + ("    " if is_last else "│   ")
                        _build(subpath, new_prefix, depth + 1)

            _build(root, "", 1)
            return "\n".join(lines)
