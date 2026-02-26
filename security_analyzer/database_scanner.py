"""Database security scanner - credentials, configs, and exposure for PostgreSQL, MySQL, Redis, MongoDB."""
import subprocess
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class DatabaseScanner:
    """Audits database services for authentication weaknesses, misconfigs, and data exposure."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Database Scanner")
        can_ssh = self._can_connect()
        result.raw_output += f"SSH access: {'yes' if can_ssh else 'no'}\n\n"

        self._check_postgres(result, via_ssh=can_ssh)
        self._check_mysql(result, via_ssh=can_ssh)
        self._check_redis(result, via_ssh=can_ssh)
        self._check_mongodb(result, via_ssh=can_ssh)

        if can_ssh:
            self._check_docker_databases(result)
            self._check_db_backup_files(result)
            self._check_db_credentials_in_configs(result)

        return result

    # ------------------------------------------------------------------ helpers

    def _can_connect(self) -> bool:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", "echo ok"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def _run_remote(self, command: str, timeout: int = 30) -> Optional[str]:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", command])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.stdout if proc.returncode == 0 else proc.stderr
        except subprocess.TimeoutExpired:
            return None

    # -------------------------------------------------------------- PostgreSQL

    def _check_postgres(self, result: ScanResult, via_ssh: bool):
        result.raw_output += "--- PostgreSQL Audit ---\n"

        if not via_ssh:
            return

        pg_proc = self._run_remote(
            "ps aux 2>/dev/null | grep -E '[p]ostgres' | head -5"
        )
        if not pg_proc or not pg_proc.strip():
            result.raw_output += "PostgreSQL: not detected\n"
            return

        result.raw_output += f"PostgreSQL processes:\n{pg_proc}\n"

        # --- Unauthenticated access (no password prompt) ---
        psql_test = self._run_remote(
            "psql -U postgres -h 127.0.0.1 -p 5432 -w -c 'SELECT 1;' 2>&1 | head -3"
        )
        if psql_test and ("1 row" in psql_test or "t" == psql_test.strip()):
            result.add_finding(Finding(
                title="PostgreSQL: No Password Required for Default 'postgres' User",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="Connected to PostgreSQL as 'postgres' without a password. "
                            "Full database access is available to any local process.",
                evidence=psql_test.strip()[:200],
                recommendation="Set a strong password: ALTER USER postgres PASSWORD 'strongpassword'; "
                               "and update pg_hba.conf to use 'md5' or 'scram-sha-256'.",
                cwe_id="CWE-521",
                cvss_score=9.8,
            ))

        # --- pg_hba.conf: trust authentication ---
        pghba = self._run_remote(
            "cat /etc/postgresql/*/main/pg_hba.conf "
            "/var/lib/pgsql/data/pg_hba.conf "
            "/var/lib/pgsql/*/data/pg_hba.conf 2>/dev/null "
            "| grep -vE '^[[:space:]]*(#|$)' | head -30"
        )
        if pghba:
            result.raw_output += f"pg_hba.conf (active lines):\n{pghba}\n"
            trust_lines = [l for l in pghba.splitlines() if "trust" in l.lower()]
            if trust_lines:
                result.add_finding(Finding(
                    title="PostgreSQL: 'trust' Authentication in pg_hba.conf",
                    severity=Severity.CRITICAL,
                    category=Category.DATABASE,
                    description="pg_hba.conf contains 'trust' entries — any connection matching "
                                "those rules is accepted without a password.",
                    evidence="\n".join(trust_lines)[:300],
                    recommendation="Replace 'trust' with 'scram-sha-256' or 'md5' in pg_hba.conf, "
                                   "then reload: SELECT pg_reload_conf();",
                    cwe_id="CWE-287",
                    cvss_score=9.1,
                ))

        # --- postgresql.conf: listen_addresses, SSL, logging ---
        pgconf = self._run_remote(
            "cat /etc/postgresql/*/main/postgresql.conf "
            "/var/lib/pgsql/data/postgresql.conf "
            "/var/lib/pgsql/*/data/postgresql.conf 2>/dev/null "
            "| grep -vE '^[[:space:]]*(#|$)' "
            "| grep -E '(listen_addresses|ssl|log_connections|log_disconnections"
            "|password_encryption|log_line_prefix)' | head -20"
        )
        if pgconf:
            result.raw_output += f"postgresql.conf (key settings):\n{pgconf}\n"

            if "listen_addresses = '*'" in pgconf or "listen_addresses='*'" in pgconf:
                result.add_finding(Finding(
                    title="PostgreSQL: Listening on All Interfaces",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="PostgreSQL is configured to accept connections on all network "
                                "interfaces. It should be restricted to localhost or private IPs.",
                    evidence="listen_addresses = '*'",
                    recommendation="Set listen_addresses = 'localhost' or a specific private IP, "
                                   "then reload PostgreSQL.",
                    cwe_id="CWE-284",
                ))

            if "ssl = off" in pgconf.replace(" ", "").lower():
                result.add_finding(Finding(
                    title="PostgreSQL: SSL/TLS Disabled",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="PostgreSQL SSL is disabled. Database traffic is transmitted "
                                "in plaintext, exposing credentials and query data.",
                    evidence="ssl = off",
                    recommendation="Enable SSL: set ssl = on in postgresql.conf and provide "
                                   "ssl_cert_file and ssl_key_file.",
                    cwe_id="CWE-319",
                ))

            if "log_connections" not in pgconf:
                result.add_finding(Finding(
                    title="PostgreSQL: Connection Logging Disabled",
                    severity=Severity.LOW,
                    category=Category.DATABASE,
                    description="log_connections is not enabled. Failed and successful "
                                "authentication attempts are not logged, hindering intrusion detection.",
                    evidence="log_connections not set in postgresql.conf",
                    recommendation="Set log_connections = on and log_disconnections = on.",
                    cwe_id="CWE-778",
                ))

            if "password_encryption" in pgconf and "md5" in pgconf:
                result.add_finding(Finding(
                    title="PostgreSQL: Weak Password Hashing (MD5)",
                    severity=Severity.MEDIUM,
                    category=Category.DATABASE,
                    description="PostgreSQL is using MD5 for password hashing, which is "
                                "vulnerable to offline cracking. SCRAM-SHA-256 is recommended.",
                    evidence="password_encryption = md5",
                    recommendation="Set password_encryption = scram-sha-256, reset all passwords, "
                                   "and update pg_hba.conf to use scram-sha-256.",
                    cwe_id="CWE-916",
                ))

        # --- Superuser accounts ---
        superusers = self._run_remote(
            "psql -U postgres -h 127.0.0.1 -p 5432 -w -t "
            "-c \"SELECT usename FROM pg_user WHERE usesuper=true;\" 2>&1 | head -10"
        )
        if superusers and "psql:" not in superusers:
            result.raw_output += f"PostgreSQL superusers: {superusers.strip()}\n"
            su_list = [u.strip() for u in superusers.strip().splitlines() if u.strip()]
            if len(su_list) > 1:
                result.add_finding(Finding(
                    title=f"PostgreSQL: Multiple Superuser Accounts ({len(su_list)})",
                    severity=Severity.MEDIUM,
                    category=Category.DATABASE,
                    description=f"Found {len(su_list)} PostgreSQL superuser accounts. "
                                "Each superuser has unrestricted access to all databases.",
                    evidence=f"Superusers: {', '.join(su_list[:5])}",
                    recommendation="Revoke superuser from non-essential accounts: "
                                   "ALTER USER <name> NOSUPERUSER;",
                    cwe_id="CWE-250",
                ))

    # ------------------------------------------------------------------ MySQL

    def _check_mysql(self, result: ScanResult, via_ssh: bool):
        result.raw_output += "\n--- MySQL/MariaDB Audit ---\n"

        if not via_ssh:
            return

        mysql_proc = self._run_remote(
            "ps aux 2>/dev/null | grep -E '[m]ysqld|[m]ariadbd' | head -5"
        )
        if not mysql_proc or not mysql_proc.strip():
            result.raw_output += "MySQL/MariaDB: not detected\n"
            return

        result.raw_output += f"MySQL processes:\n{mysql_proc}\n"

        # --- Try root with empty password ---
        root_test = self._run_remote(
            "mysql -h 127.0.0.1 -u root --password='' -e 'SELECT 1;' 2>&1 | head -3"
        )
        if root_test and "1" in root_test and "ERROR" not in root_test:
            result.add_finding(Finding(
                title="MySQL: Root Login With Empty Password",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="MySQL root account has no password set. "
                            "Any local process can gain full database control.",
                evidence="mysql -u root --password='' connected successfully",
                recommendation="Set root password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_pass'; "
                               "FLUSH PRIVILEGES;",
                cwe_id="CWE-521",
                cvss_score=9.8,
            ))

        # --- Anonymous users ---
        anon_users = self._run_remote(
            "mysql -h 127.0.0.1 -u root --password='' "
            "-e \"SELECT host, user FROM mysql.user WHERE user='';\" 2>&1 | head -10"
        )
        if anon_users and "host" not in anon_users.lower() and "ERROR" not in anon_users:
            if anon_users.strip():
                result.add_finding(Finding(
                    title="MySQL: Anonymous User Accounts Exist",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="MySQL has anonymous user accounts (user=''). "
                                "These allow unauthenticated access to the database.",
                    evidence=anon_users.strip()[:200],
                    recommendation="Remove anonymous accounts: DELETE FROM mysql.user WHERE user=''; "
                                   "FLUSH PRIVILEGES;",
                    cwe_id="CWE-287",
                ))
        elif anon_users and "user" in anon_users.lower() and anon_users.count("\n") > 1:
            result.add_finding(Finding(
                title="MySQL: Anonymous User Accounts Exist",
                severity=Severity.HIGH,
                category=Category.DATABASE,
                description="Anonymous MySQL user accounts found.",
                evidence=anon_users.strip()[:200],
                recommendation="DELETE FROM mysql.user WHERE user=''; FLUSH PRIVILEGES;",
                cwe_id="CWE-287",
            ))

        # --- Test database ---
        test_db = self._run_remote(
            "mysql -h 127.0.0.1 -u root --password='' "
            "-e \"SHOW DATABASES LIKE 'test';\" 2>&1 | head -5"
        )
        if test_db and "test" in test_db and "ERROR" not in test_db:
            result.add_finding(Finding(
                title="MySQL: Test Database Exists",
                severity=Severity.LOW,
                category=Category.DATABASE,
                description="The 'test' database exists and is accessible to all users by default. "
                            "It can be used to consume disk space or as an initial foothold.",
                evidence="SHOW DATABASES returned 'test'",
                recommendation="Drop the test database: DROP DATABASE test; "
                               "DELETE FROM mysql.db WHERE Db='test%'; FLUSH PRIVILEGES;",
                cwe_id="CWE-1188",
            ))

        # --- my.cnf: bind-address, skip-networking ---
        mycnf = self._run_remote(
            "cat /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf "
            "/etc/my.cnf /etc/my.cnf.d/server.cnf 2>/dev/null "
            "| grep -vE '^[[:space:]]*(#|$)' "
            "| grep -iE '(bind.address|skip.networking|ssl|require_secure_transport"
            "|general.log|slow.query.log)' | head -20"
        )
        if mycnf:
            result.raw_output += f"MySQL config (key settings):\n{mycnf}\n"

            if "0.0.0.0" in mycnf or ("bind-address" not in mycnf and "bind_address" not in mycnf):
                result.add_finding(Finding(
                    title="MySQL: Potentially Bound to All Interfaces",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="MySQL bind-address is not explicitly restricted to localhost. "
                                "The database may be accepting remote connections.",
                    evidence=mycnf.strip()[:200],
                    recommendation="Set bind-address = 127.0.0.1 in [mysqld] section of my.cnf.",
                    cwe_id="CWE-284",
                ))

            if "require_secure_transport" not in mycnf and "ssl" not in mycnf.lower():
                result.add_finding(Finding(
                    title="MySQL: SSL/TLS Not Enforced",
                    severity=Severity.MEDIUM,
                    category=Category.DATABASE,
                    description="MySQL does not appear to enforce SSL/TLS for client connections.",
                    evidence="require_secure_transport and ssl settings not found in config",
                    recommendation="Add require_secure_transport = ON to my.cnf and configure "
                                   "ssl-ca, ssl-cert, ssl-key paths.",
                    cwe_id="CWE-319",
                ))

    # -------------------------------------------------------------------- Redis

    def _check_redis(self, result: ScanResult, via_ssh: bool):
        result.raw_output += "\n--- Redis Audit ---\n"

        if not via_ssh:
            return

        redis_proc = self._run_remote(
            "ps aux 2>/dev/null | grep -E '[r]edis-server' | head -5"
        )
        if not redis_proc or not redis_proc.strip():
            result.raw_output += "Redis: not detected\n"
            return

        result.raw_output += f"Redis processes:\n{redis_proc}\n"

        # --- Unauthenticated PING ---
        ping_resp = self._run_remote(
            "timeout 2 bash -c "
            "'printf \"*1\\r\\n\\$4\\r\\nPING\\r\\n\" | nc -w2 127.0.0.1 6379 2>/dev/null'"
        )
        if ping_resp and "+PONG" in ping_resp:
            result.add_finding(Finding(
                title="Redis: No Authentication Required (Unauthenticated Access)",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="Redis responded to PING without any authentication. "
                            "An attacker can read/write all data, execute Lua scripts, "
                            "and potentially write SSH keys or cron jobs for RCE.",
                evidence="PING -> +PONG without AUTH",
                recommendation="Set requirepass in redis.conf: requirepass <strong_password>. "
                               "Also set bind 127.0.0.1 to restrict to localhost.",
                cwe_id="CWE-306",
                cvss_score=9.8,
            ))

            # If unauthenticated, try CONFIG GET to show further exposure
            config_resp = self._run_remote(
                "timeout 2 bash -c "
                "'printf \"*3\\r\\n\\$6\\r\\nCONFIG\\r\\n\\$3\\r\\nGET\\r\\n"
                "\\$4\\r\\ndir\\r\\n\" | nc -w2 127.0.0.1 6379 2>/dev/null'"
            )
            if config_resp and "dir" in config_resp:
                result.add_finding(Finding(
                    title="Redis: CONFIG Command Accessible Without Auth",
                    severity=Severity.CRITICAL,
                    category=Category.DATABASE,
                    description="The Redis CONFIG command is accessible without authentication. "
                                "An attacker can use CONFIG SET dir/dbfilename to write arbitrary "
                                "files to disk (e.g., SSH authorized_keys, cron jobs).",
                    evidence=f"CONFIG GET dir returned: {config_resp.strip()[:150]}",
                    recommendation="Disable CONFIG: rename-command CONFIG '' in redis.conf. "
                                   "Enable authentication and bind to localhost.",
                    cwe_id="CWE-732",
                    cvss_score=9.8,
                ))

        elif ping_resp and "NOAUTH" in ping_resp:
            result.raw_output += "Redis: authentication required (NOAUTH response)\n"

        # --- redis.conf: requirepass, bind, protected-mode ---
        redis_conf = self._run_remote(
            "cat /etc/redis/redis.conf /etc/redis.conf "
            "/usr/local/etc/redis/redis.conf 2>/dev/null "
            "| grep -vE '^[[:space:]]*(#|$)' "
            "| grep -iE '(requirepass|bind|protected.mode|rename.command"
            "|logfile|loglevel|maxmemory)' | head -20"
        )
        if redis_conf:
            result.raw_output += f"redis.conf (key settings):\n{redis_conf}\n"

            if "requirepass" not in redis_conf:
                result.add_finding(Finding(
                    title="Redis: requirepass Not Set in Config",
                    severity=Severity.CRITICAL,
                    category=Category.DATABASE,
                    description="Redis config does not have requirepass set, meaning no "
                                "password is required to connect.",
                    evidence="requirepass not found in redis.conf",
                    recommendation="Add requirepass <strong_random_password> to redis.conf "
                                   "and restart Redis.",
                    cwe_id="CWE-306",
                ))

            if "protected-mode no" in redis_conf.lower():
                result.add_finding(Finding(
                    title="Redis: Protected Mode Disabled",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="Redis protected-mode is disabled. Without a password and bind "
                                "restriction, Redis is accessible to any external host.",
                    evidence="protected-mode no",
                    recommendation="Enable protected mode: protected-mode yes, or set bind + requirepass.",
                    cwe_id="CWE-284",
                ))

            if "bind 127.0.0.1" not in redis_conf and "bind 0.0.0.0" not in redis_conf:
                result.add_finding(Finding(
                    title="Redis: Bind Address Not Explicitly Set",
                    severity=Severity.MEDIUM,
                    category=Category.DATABASE,
                    description="Redis bind address is not explicitly configured to localhost. "
                                "It may accept connections from all interfaces.",
                    evidence="bind directive absent or ambiguous in redis.conf",
                    recommendation="Add 'bind 127.0.0.1 ::1' to redis.conf.",
                    cwe_id="CWE-284",
                ))

    # ----------------------------------------------------------------- MongoDB

    def _check_mongodb(self, result: ScanResult, via_ssh: bool):
        result.raw_output += "\n--- MongoDB Audit ---\n"

        if not via_ssh:
            return

        mongo_proc = self._run_remote(
            "ps aux 2>/dev/null | grep -E '[m]ongod' | head -5"
        )
        if not mongo_proc or not mongo_proc.strip():
            result.raw_output += "MongoDB: not detected\n"
            return

        result.raw_output += f"MongoDB processes:\n{mongo_proc}\n"

        # --- Unauthenticated access ---
        mongo_test = self._run_remote(
            "mongosh --quiet --norc "
            "--eval 'db.adminCommand({listDatabases:1}).databases.map(d=>d.name)' "
            "2>/dev/null | head -5"
        )
        if not mongo_test or "MongoServerError" in (mongo_test or "") or "Authentication" in (mongo_test or ""):
            # Try older mongo client
            mongo_test = self._run_remote(
                "mongo --quiet --eval 'printjson(db.adminCommand({listDatabases:1}))' "
                "2>/dev/null | head -5"
            )

        if mongo_test and mongo_test.strip() and "Authentication" not in mongo_test \
                and "Error" not in mongo_test and "error" not in mongo_test:
            result.add_finding(Finding(
                title="MongoDB: No Authentication Required (Unauthenticated Access)",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="Connected to MongoDB without credentials and listed databases. "
                            "All data is readable and writable without authentication.",
                evidence=mongo_test.strip()[:250],
                recommendation="Enable authentication in mongod.conf: security.authorization: enabled. "
                               "Create an admin user before enabling auth.",
                cwe_id="CWE-306",
                cvss_score=9.8,
            ))

        # --- mongod.conf: auth, bindIp, TLS ---
        mongocnf = self._run_remote(
            "cat /etc/mongod.conf /etc/mongodb.conf "
            "/usr/local/etc/mongod.conf 2>/dev/null | head -60"
        )
        if mongocnf:
            result.raw_output += f"mongod.conf:\n{mongocnf[:600]}\n"

            if "authorization: enabled" not in mongocnf and "auth = true" not in mongocnf:
                result.add_finding(Finding(
                    title="MongoDB: authorization Not Enabled in Config",
                    severity=Severity.CRITICAL,
                    category=Category.DATABASE,
                    description="mongod.conf does not have authorization enabled. "
                                "Authentication is not enforced at the config level.",
                    evidence="security.authorization: enabled not found in mongod.conf",
                    recommendation="Add to mongod.conf:\n  security:\n    authorization: enabled",
                    cwe_id="CWE-306",
                ))

            if "bindIp: 0.0.0.0" in mongocnf or "bind_ip = 0.0.0.0" in mongocnf:
                result.add_finding(Finding(
                    title="MongoDB: Bound to All Interfaces (0.0.0.0)",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description="MongoDB is configured to accept connections on all network "
                                "interfaces, making it reachable from outside the host.",
                    evidence="bindIp: 0.0.0.0",
                    recommendation="Change bindIp to 127.0.0.1 or private IP only.",
                    cwe_id="CWE-284",
                ))

            if "tls:" not in mongocnf and "ssl:" not in mongocnf \
                    and "mode: requireTLS" not in mongocnf:
                result.add_finding(Finding(
                    title="MongoDB: TLS Not Configured",
                    severity=Severity.MEDIUM,
                    category=Category.DATABASE,
                    description="MongoDB TLS/SSL is not configured. "
                                "Data and credentials are transmitted in plaintext.",
                    evidence="tls/ssl section not found in mongod.conf",
                    recommendation="Configure TLS in mongod.conf:\n  net:\n    tls:\n"
                                   "      mode: requireTLS\n      certificateKeyFile: /path/to/cert.pem",
                    cwe_id="CWE-319",
                ))

        # Check --auth flag in process args
        if "--noauth" in (mongo_proc or ""):
            result.add_finding(Finding(
                title="MongoDB: Running with --noauth Flag",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="MongoDB is explicitly started with --noauth, disabling all "
                            "access control regardless of config file settings.",
                evidence=f"Process args contain --noauth",
                recommendation="Remove --noauth from startup arguments and enable "
                               "security.authorization in mongod.conf.",
                cwe_id="CWE-306",
                cvss_score=9.8,
            ))

    # -------------------------------------------------- Docker DB containers

    def _check_docker_databases(self, result: ScanResult):
        result.raw_output += "\n--- Docker Database Containers ---\n"

        containers = self._run_remote(
            "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Ports}}\\t{{.Status}}' 2>/dev/null"
        )
        if not containers or not containers.strip():
            result.raw_output += "No Docker containers found (or Docker not available)\n"
            return

        result.raw_output += containers + "\n"

        db_images = ["postgres", "mysql", "mariadb", "redis", "mongo", "elasticsearch",
                     "cassandra", "couchdb", "influxdb", "memcached", "mssql"]

        for line in containers.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, image, ports = parts[0], parts[1], parts[2]

            if not any(db in image.lower() for db in db_images):
                continue

            result.raw_output += f"DB container: {name} ({image}) ports: {ports}\n"

            # Check if DB port is exposed on 0.0.0.0
            if "0.0.0.0" in ports:
                result.add_finding(Finding(
                    title=f"Docker DB Container Exposed on All Interfaces: {name}",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description=f"Database container '{name}' ({image}) is publishing ports "
                                "on 0.0.0.0, making the database reachable from external hosts.",
                    evidence=f"Container: {name}, Image: {image}, Ports: {ports}",
                    recommendation="Use 127.0.0.1:port:port mapping. "
                                   "Example: -p 127.0.0.1:5432:5432",
                    cwe_id="CWE-284",
                ))

            # Check for default credentials in environment variables
            env_out = self._run_remote(
                f"docker inspect {name} 2>/dev/null | "
                "python3 -c \""
                "import sys,json; "
                "cfg=json.load(sys.stdin); "
                "[print(e) for c in cfg "
                "for e in c.get('Config',{}).get('Env',[]) "
                "if any(k in e.upper() for k in ['PASSWORD','PASS','SECRET','TOKEN'])"
                "\" 2>/dev/null"
            )
            if env_out and env_out.strip():
                result.add_finding(Finding(
                    title=f"Docker DB Container Has Password in Environment: {name}",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    description=f"Container '{name}' ({image}) has database credentials "
                                "stored as environment variables, which are visible via "
                                "docker inspect.",
                    evidence=f"Env vars with credentials found in container {name}",
                    recommendation="Use Docker secrets or a secrets manager instead of "
                                   "environment variables for database credentials.",
                    cwe_id="CWE-798",
                ))

            # Flag containers with default well-known passwords
            if env_out:
                defaults = ["password", "root", "admin", "test", "secret", "12345", "changeme"]
                for default in defaults:
                    if f"={default}" in env_out.lower() or f"={default}\n" in env_out.lower():
                        result.add_finding(Finding(
                            title=f"Docker DB Container Uses Default/Weak Password: {name}",
                            severity=Severity.CRITICAL,
                            category=Category.DATABASE,
                            description=f"Container '{name}' appears to use a default or "
                                        f"weak password ('{default}'). "
                                        "This is trivially guessable.",
                            evidence=f"Default credential pattern detected in container env",
                            recommendation="Set a strong, unique password for each database container.",
                            cwe_id="CWE-1188",
                            cvss_score=9.1,
                        ))
                        break

    # ------------------------------------------------- Backup file exposure

    def _check_db_backup_files(self, result: ScanResult):
        result.raw_output += "\n--- Database Backup Files ---\n"

        backup_files = self._run_remote(
            "find /tmp /var/backups /opt /srv /home /root /backup /data "
            "-maxdepth 5 -type f "
            r"\( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' "
            r"-o -name '*.bak' -o -name '*.rdb' -o -name '*.mongodump' "
            r"-o -name 'dump.rdb' \) "
            "2>/dev/null | head -20"
        )
        if backup_files and backup_files.strip():
            result.add_finding(Finding(
                title="Database Backup Files Found on Filesystem",
                severity=Severity.HIGH,
                category=Category.DATABASE,
                description="Database backup/dump files were found on the filesystem. "
                            "These files may contain sensitive data and are accessible "
                            "to users with filesystem access.",
                evidence=backup_files.strip()[:400],
                recommendation="Move backups to encrypted, access-controlled storage. "
                               "Remove backups from application servers. "
                               "Encrypt backups at rest.",
                cwe_id="CWE-530",
            ))
        else:
            result.raw_output += "No database backup files found in common locations\n"

    # ---------------------------------------- Hardcoded DB credentials in configs

    def _check_db_credentials_in_configs(self, result: ScanResult):
        result.raw_output += "\n--- Hardcoded DB Credentials in Config Files ---\n"

        # Search for DB connection strings / credentials in common config locations
        cred_files = self._run_remote(
            r"grep -rlE "
            r"'(jdbc:|mongodb://|postgresql://|mysql://|redis://|"
            r"DB_PASS|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD"
            r"|db\.password|datasource\.password)[^\s]*[\"'\'':\s][^\"'\'']{3,}' "
            "/opt /srv /app /home /etc "
            r"--include='*.properties' --include='*.yml' --include='*.yaml' "
            r"--include='*.xml' --include='*.conf' --include='*.env' --include='*.json' "
            "2>/dev/null | grep -v '.class' | head -15"
        )
        if cred_files and cred_files.strip():
            result.add_finding(Finding(
                title="Database Credentials Found in Config Files",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                description="Configuration files containing database credentials or connection "
                            "strings with passwords were found. These are accessible to anyone "
                            "with read access to those files.",
                evidence=f"Files: {cred_files.strip()[:400]}",
                recommendation="Move all database credentials to environment variables "
                               "or a secrets manager (HashiCorp Vault, AWS Secrets Manager). "
                               "Rotate any credentials found in plaintext.",
                cwe_id="CWE-798",
                cvss_score=8.0,
            ))
        else:
            result.raw_output += "No hardcoded DB credentials found in config files\n"
