"""Stateful Virtual Filesystem (VFS) for the SSH honeypot shell."""

from __future__ import annotations
from typing import Any, Dict, List


class VirtualFilesystem:
    def __init__(self) -> None:
        # A dictionary mapping absolute paths of files to their content (bytes)
        # and directories to True.
        self.fs: Dict[str, Any] = {
            "/": True,
            "/bin": True,
            "/etc": True,
            "/home": True,
            "/home/ubuntu": True,
            "/proc": True,
            "/root": True,
            "/tmp": True,
            "/usr": True,
            "/usr/local": True,
            "/usr/local/bin": True,
            "/var": True,
            "/var/log": True,
            "/var/www": True,
            "/var/www/html": True,

            # --- /root files ---
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
            "/root/.ssh": True,
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
            "/etc/resolv.conf": b"nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch internal\n",
            "/etc/shadow": (
                b"root:$6$fakeSalt0001$FakeHashedPasswordRoot0001XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
                b"ubuntu:$6$fakeSalt0002$FakeHashedPasswordUbuntu002XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
                b"deploy:$6$fakeSalt0003$FakeHashedPasswordDeploy003XXXXXXXXXXXXXXXXXXX:19500:0:99999:7:::\n"
            ),
            "/etc/nginx": True,
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
            "/var/log/nginx": True,
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
        }

    def _normalize_path(self, cwd: str, path: str) -> str:
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

    def exists(self, path: str) -> bool:
        return path in self.fs

    def is_dir(self, path: str) -> bool:
        return self.fs.get(path) is True

    def is_file(self, path: str) -> bool:
        return isinstance(self.fs.get(path), bytes)

    def list_dir(self, path: str) -> List[str] | None:
        if not self.is_dir(path):
            return None
        prefix = path if path.endswith("/") else path + "/"
        res = []
        for k in self.fs.keys():
            if k == path:
                continue
            if k.startswith(prefix):
                sub = k[len(prefix):]
                item = sub.split("/")[0]
                if item not in res:
                    res.append(item)
        return sorted(res)

    def read_file(self, path: str) -> bytes | None:
        if self.is_file(path):
            return self.fs[path]
        return None

    def stat(self, path: str) -> dict[str, Any] | None:
        """Return lightweight POSIX-like metadata for a virtual path."""
        if path not in self.fs:
            return None
        is_dir = self.is_dir(path)
        return {
            "path": path,
            "name": path.rstrip("/").split("/")[-1] or "/",
            "type": "directory" if is_dir else "file",
            "size": 4096 if is_dir else len(self.read_file(path) or b""),
            "mode": "drwxr-xr-x" if is_dir else "-rw-r--r--",
        }

    def copy(self, source: str, destination: str) -> bool:
        """Copy a file inside the virtual filesystem."""
        if not self.is_file(source) or self.is_dir(destination):
            return False
        content = self.read_file(source)
        if content is None:
            return False
        return self.write_file(destination, content)

    def move(self, source: str, destination: str) -> bool:
        """Move or rename a file or empty directory inside the virtual filesystem."""
        if source == "/" or source not in self.fs or destination in self.fs:
            return False
        parent = "/".join(destination.split("/")[:-1]) or "/"
        if not self.is_dir(parent):
            return False
        if self.is_file(source):
            self.fs[destination] = self.fs.pop(source)
            return True
        if self.is_dir(source):
            prefix = source if source.endswith("/") else source + "/"
            children = [k for k in self.fs if k != source and k.startswith(prefix)]
            if children:
                return False
            self.fs[destination] = self.fs.pop(source)
            return True
        return False

    def write_file(self, path: str, content: bytes) -> bool:
        parent = "/".join(path.split("/")[:-1])
        if not parent:
            parent = "/"
        if not self.is_dir(parent):
            return False
        if self.is_dir(path):
            return False
        self.fs[path] = content
        return True

    def mkdir(self, path: str) -> bool:
        parent = "/".join(path.split("/")[:-1])
        if not parent:
            parent = "/"
        if not self.is_dir(parent):
            return False
        if path in self.fs:
            return False
        self.fs[path] = True
        return True

    def rm(self, path: str) -> bool:
        if self.is_file(path):
            del self.fs[path]
            return True
        return False

    def rmdir(self, path: str) -> bool:
        if self.is_dir(path):
            prefix = path if path.endswith("/") else path + "/"
            for k in self.fs.keys():
                if k != path and k.startswith(prefix):
                    return False
            del self.fs[path]
            return True
        return False

    def grep(self, pattern: str, path: str) -> list[str]:
        """Simple grep: return lines containing pattern in a file."""
        content = self.read_file(path)
        if content is None:
            return []
        lines = content.decode("utf-8", errors="replace").splitlines()
        return [line for line in lines if pattern.lower() in line.lower()]

    def find(self, root: str, name_pattern: str | None = None) -> list[str]:
        """Return all paths under root, optionally filtered by name substring."""
        prefix = root if root.endswith("/") else root + "/"
        results = []
        for k in self.fs:
            if k == root or k.startswith(prefix):
                if name_pattern is None or name_pattern in k.split("/")[-1]:
                    results.append(k)
        return sorted(results)
