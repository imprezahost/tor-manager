# coding: utf-8
# Tor Service Manager - aaPanel Plugin v3.4

import sys
import os
import hashlib
import json
import re
import shutil
import subprocess
import time


class tor_manager_main:
    __plugin_path = '/www/server/panel/plugin/tor_manager'

    __tor_bin_paths = [
        '/usr/bin/tor', '/usr/sbin/tor', '/usr/local/bin/tor',
        '/usr/local/sbin/tor', '/snap/bin/tor',
    ]

    __torrc_options = [
        {'key': 'SocksPort', 'label': 'SOCKS Proxy Port', 'desc': 'Port where Tor listens for local SOCKS connections. Apps route traffic through Tor via this port. Set to 0 to disable.', 'default': '9050', 'type': 'text', 'category': 'network'},
        {'key': 'SocksPolicy', 'label': 'SOCKS Access Policy', 'desc': 'Controls who can connect to the SOCKS port. Example: "accept 127.0.0.1, reject *" allows only localhost.', 'default': '', 'type': 'text', 'category': 'network'},
        {'key': 'Log', 'label': 'Log Level & Destination', 'desc': 'Where and how verbose Tor logs. Examples: "notice file /var/log/tor/notices.log", "notice syslog". Levels: debug, info, notice, warn, err.', 'default': 'notice file /var/log/tor/notices.log', 'type': 'text', 'category': 'general'},
        {'key': 'RunAsDaemon', 'label': 'Run as Daemon', 'desc': 'Run Tor in the background. Usually handled by systemd so not needed.', 'default': '0', 'type': 'bool', 'category': 'general'},
        {'key': 'DataDirectory', 'label': 'Data Directory', 'desc': 'Where Tor stores state data, keys, and cache. Default: /var/lib/tor.', 'default': '/var/lib/tor', 'type': 'text', 'category': 'general'},
        {'key': 'HiddenServiceDir', 'label': 'Hidden Service Directory', 'desc': 'Directory where Tor stores your .onion hostname and private keys. Each hidden service needs its own directory. The Tor user must own this folder.', 'default': '/var/lib/tor/hidden_service/', 'type': 'text', 'category': 'hidden_service'},
        {'key': 'HiddenServicePort', 'label': 'Hidden Service Port Mapping', 'desc': 'Maps a virtual port on your .onion to a local address:port. Format: "VIRTUAL_PORT [TARGET:]PORT". Example: "80 127.0.0.1:80" forwards .onion:80 to localhost:80.', 'default': '', 'type': 'text', 'category': 'hidden_service', 'multi': True},
        {'key': 'HiddenServiceVersion', 'label': 'Hidden Service Version', 'desc': 'Protocol version. Version 3 (default) has stronger crypto and 56-char .onion addresses. Version 2 is deprecated.', 'default': '3', 'type': 'select', 'options': ['2', '3'], 'category': 'hidden_service'},
        {'key': 'HiddenServiceAuthorizeClient', 'label': 'Client Authorization', 'desc': 'Restrict access to specific clients. Format: "auth-type client-name,...". Types: basic, stealth.', 'default': '', 'type': 'text', 'category': 'hidden_service'},
        {'key': 'ControlPort', 'label': 'Control Port', 'desc': 'TCP port for Tor control protocol. Allows tools like Nyx or stem to monitor Tor. Usually 9051. Leave empty to disable.', 'default': '', 'type': 'text', 'category': 'advanced'},
        {'key': 'HashedControlPassword', 'label': 'Control Password (Hashed)', 'desc': 'Hashed password for control port. Generate with: tor --hash-password YOUR_PASSWORD.', 'default': '', 'type': 'text', 'category': 'advanced'},
        {'key': 'CookieAuthentication', 'label': 'Cookie Authentication', 'desc': 'Allow control port access using a cookie file instead of password.', 'default': '0', 'type': 'bool', 'category': 'advanced'},
        {'key': 'MaxCircuitDirtiness', 'label': 'Max Circuit Lifetime (sec)', 'desc': 'Seconds before Tor builds a new circuit. Lower = more anonymity but slower. Default: 600 (10 min).', 'default': '600', 'type': 'text', 'category': 'performance'},
        {'key': 'CircuitBuildTimeout', 'label': 'Circuit Build Timeout (sec)', 'desc': 'Seconds Tor waits for a circuit before giving up. Lower = faster failover.', 'default': '', 'type': 'text', 'category': 'performance'},
        {'key': 'NumEntryGuards', 'label': 'Number of Entry Guards', 'desc': 'How many entry guards to use. Default: 1.', 'default': '1', 'type': 'text', 'category': 'performance'},
        {'key': 'ExitPolicy', 'label': 'Exit Policy', 'desc': 'Only for relays/exits. Controls what traffic your exit allows. "reject *:*" blocks all exit traffic.', 'default': '', 'type': 'text', 'category': 'relay'},
        {'key': 'ORPort', 'label': 'Relay OR Port', 'desc': 'Setting this turns your server into a Tor relay. Leave empty unless you intend to run a relay.', 'default': '', 'type': 'text', 'category': 'relay'},
        {'key': 'Nickname', 'label': 'Relay Nickname', 'desc': 'A name for your relay visible in the Tor network. Only for relays.', 'default': '', 'type': 'text', 'category': 'relay'},
        {'key': 'ContactInfo', 'label': 'Relay Contact Info', 'desc': 'Contact info if you run a relay. Example: "admin@example.com".', 'default': '', 'type': 'text', 'category': 'relay'},
        {'key': 'BridgeRelay', 'label': 'Bridge Relay', 'desc': 'Makes your relay a bridge (not listed publicly). Helps censored users connect to Tor.', 'default': '0', 'type': 'bool', 'category': 'relay'},
    ]

    __exec_path = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'

    # Scratch files live here, not in /tmp. Two reasons, and the second is the
    # serious one: the shell scripts below are executed as root, so a predictable
    # name in a world-writable directory is a local privilege escalation; and
    # vanity generation writes freshly minted ed25519 secret keys, which have no
    # business sitting where every account on the box can read them.
    __work_dir = '/var/lib/tor_manager'

    def _work_dir(self):
        """Return the scratch directory, creating it root-only if needed."""
        try:
            os.makedirs(self.__work_dir, mode=0o700, exist_ok=True)
            os.chmod(self.__work_dir, 0o700)
        except Exception:
            pass
        return self.__work_dir

    def _work_path(self, name):
        return os.path.join(self._work_dir(), name)

    def _purge_legacy_tmp(self):
        """Remove scratch files that earlier versions wrote to /tmp."""
        self._exec('rm -rf /tmp/tor_vanity_* /tmp/mkp224o_bench_* 2>/dev/null')
        self._exec('rm -f /tmp/.tor_update.sh /tmp/.tor_update_status /tmp/.tor_update_log '
                   '/tmp/.webserver_switch.sh /tmp/.webserver_switch_status '
                   '/tmp/.webserver_switch_log 2>/dev/null')

    # Roots that the panel is allowed to touch. Anything derived from a request
    # argument must be resolved through _safe_path() against one of these.
    __path_roots = ('/etc/tor', '/var/lib/tor', '/var/log/tor')

    def _env(self):
        env = os.environ.copy()
        env['PATH'] = self.__exec_path
        env['HOME'] = '/root'
        return env

    def _exec(self, cmd, timeout=30):
        """Run a shell command. NEVER interpolate a request argument into `cmd`.

        This goes through `bash -c`, so a value like `/etc/tor/x"; id; echo "`
        would execute as root. Use _run() for anything carrying caller input.
        """
        try:
            r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True,
                               timeout=timeout, env=self._env())
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timed out', 1
        except Exception as e:
            return '', str(e), 1

    def _run(self, argv, timeout=30):
        """Run a command from an argv list — no shell, so no metacharacters."""
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout, env=self._env())
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timed out', 1
        except Exception as e:
            return '', str(e), 1

    def _safe_path(self, raw, roots=None):
        """Resolve `raw` and confirm it stays inside an allowed root.

        Returns (resolved_path, None) or (None, reason). realpath() collapses
        `..` and follows symlinks before the check, so neither traversal nor a
        symlink planted inside a root can escape it — a plain startswith() on
        the raw string catches neither.
        """
        raw = (raw or '').strip()
        if not raw or '\x00' in raw:
            return None, 'Invalid path.'
        if not os.path.isabs(raw):
            return None, 'Path must be absolute.'
        try:
            resolved = os.path.realpath(raw)
        except Exception as e:
            return None, 'Cannot resolve path: ' + str(e)
        for root in (roots or self.__path_roots):
            real_root = os.path.realpath(root)
            if resolved == real_root or resolved.startswith(real_root + os.sep):
                return resolved, None
        return None, 'Access denied: path is outside the allowed directories.'

    # "VIRTPORT [TARGET]" — TARGET is host:port, [v6]:port or unix:/path.
    __hs_port_re = re.compile(
        r'^\d{1,5}(?:[ \t]+(?:\[[0-9a-fA-F:]+\]:\d{1,5}|[A-Za-z0-9.\-]+:\d{1,5}|unix:/[A-Za-z0-9._/\-]+))?$')

    def _valid_hs_ports(self, ports):
        """Split a HiddenServicePort block into validated lines.

        Returns (lines, None) or (None, reason). These lines are appended to
        torrc verbatim; an unparseable one stops Tor from starting, which takes
        every hidden service on the box down with it.
        """
        lines = [l.strip() for l in (ports or '').replace('\r', '').split('\n') if l.strip()]
        if not lines:
            return None, 'At least one port mapping is required (e.g. "80 127.0.0.1:80").'
        for l in lines:
            if not self.__hs_port_re.match(l):
                return None, 'Invalid port mapping: "%s". Expected "80 127.0.0.1:80".' % l
        return lines, None

    def _valid_onion(self, hostname):
        """True for a bare v2 (16-char) or v3 (56-char) base32 .onion address."""
        h = (hostname or '').strip().lower()
        return bool(re.match(r'^[a-z2-7]{16}\.onion$', h) or re.match(r'^[a-z2-7]{56}\.onion$', h))

    def _file_exists(self, path):
        try: return os.path.isfile(path)
        except Exception: return False

    def _dir_exists(self, path):
        try: return os.path.isdir(path)
        except Exception: return False

    def _file_size(self, path):
        try: return os.path.getsize(path)
        except Exception: return 0

    # Never rendered into the panel response: a key must not reach an HTTP
    # response, or the browser cache, just because it happens to decode as text.
    __opaque_files = ('hs_ed25519_secret_key', 'hs_ed25519_public_key',
                      'hs_secret_key', 'hs_public_key', 'private_key')

    def _read_file(self, path):
        """Read a file directly. Returns (ok, content_or_error, is_binary)."""
        try:
            with open(path, 'rb') as f:
                raw = f.read()
        except Exception as e:
            return False, 'Cannot read: ' + str(e), False
        if os.path.basename(path) in self.__opaque_files:
            return True, '[Binary file]', True
        if b'\x00' in raw:
            return True, '[Binary file]', True
        try:
            return True, raw.decode('utf-8'), False
        except UnicodeDecodeError:
            return True, '[Binary file]', True

    def _write_file(self, path, content):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, ''
        except Exception as e:
            return False, str(e)

    def _backup_file(self, path):
        """Copy `path` to a timestamped .bak alongside it. Returns (bak_path, err)."""
        bak = path + '.bak.' + str(int(time.time()))
        try:
            shutil.copy2(path, bak)
            return bak, ''
        except Exception as e:
            return '', str(e)

    def _get_distro(self):
        info = {'distro': 'unknown', 'version': '', 'codename': ''}
        s, _, c = self._exec('cat /etc/os-release 2>/dev/null')
        if c == 0:
            for line in s.splitlines():
                if line.startswith('ID='): info['distro'] = line.split('=', 1)[1].strip().strip('"').lower()
                elif line.startswith('VERSION_ID='): info['version'] = line.split('=', 1)[1].strip().strip('"')
                elif line.startswith('VERSION_CODENAME='): info['codename'] = line.split('=', 1)[1].strip().strip('"')
        return info

    def _get_exec_context(self):
        ctx = {}
        for k, cmd in [('id', 'id'), ('whoami', 'whoami'), ('shell_path', 'echo $PATH'), ('pwd', 'pwd')]:
            s, _, _ = self._exec(cmd); ctx[k] = s
        ctx['python_uid'] = str(os.getuid()); ctx['python_euid'] = str(os.geteuid()); ctx['python_pid'] = str(os.getpid())
        _, _, c1 = self._exec('cat /etc/tor/torrc >/dev/null 2>&1')
        _, _, c2 = self._exec('ls /etc/tor/ >/dev/null 2>&1')
        ctx['can_read_torrc'] = 'yes' if c1 == 0 else 'no'
        ctx['can_ls_etc_tor'] = 'yes' if c2 == 0 else 'no'
        return ctx

    def _get_tor_user(self):
        """Resolve the account Tor runs as.

        The value reaches `sudo -u` and chown, and the torrc `User` line is
        admin-editable, so anything that is not a plain username is discarded
        rather than passed along.
        """
        def valid(u):
            u = (u or '').strip()
            return u if re.match(r'^[a-zA-Z0-9._-]{1,32}$', u) else ''

        ok, content, _ = self._read_file('/etc/tor/torrc')
        if ok:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('User ') and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) > 1 and valid(parts[1]):
                        return parts[1].strip()
        s, _, c = self._exec("ps -eo user:32,comm 2>/dev/null | grep -E '\\btor$' | awk '{print $1}' | head -1")
        if c == 0 and valid(s): return s.strip()
        for u in ['debian-tor', 'tor', '_tor']:
            _, _, c = self._run(['id', u])
            if c == 0: return u
        return 'root'

    def _parse_torrc(self):
        ok, content, _ = self._read_file('/etc/tor/torrc')
        if not ok: return []
        directives = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(None, 1)
            directives.append((parts[0], parts[1] if len(parts) >= 2 else ''))
        return directives

    def _get_hidden_service_dirs(self):
        dirs = []
        for key, val in self._parse_torrc():
            if key == 'HiddenServiceDir':
                dirs.append(val.rstrip('/'))
        return dirs if dirs else ['/var/lib/tor/hidden_service']

    def _get_important_files(self):
        files = [
            {'key': 'torrc', 'path': '/etc/tor/torrc', 'label': 'torrc (Main Config)', 'editable': True},
            {'key': 'torrc_defaults', 'path': '/etc/tor/torrc-defaults', 'label': 'torrc-defaults', 'editable': True},
        ]
        hs_dirs = self._get_hidden_service_dirs()
        for i, d in enumerate(hs_dirs):
            sfx = '' if len(hs_dirs) == 1 else ' #%d' % (i + 1)
            dn = d.rstrip('/').split('/')[-1]
            files.append({'key': 'hostname_%d' % i, 'path': d + '/hostname', 'label': 'Hostname (.onion)%s — %s' % (sfx, dn), 'editable': False})
            files.append({'key': 'hs_secret_%d' % i, 'path': d + '/hs_ed25519_secret_key', 'label': 'HS Secret Key%s' % sfx, 'editable': False})
            files.append({'key': 'hs_public_%d' % i, 'path': d + '/hs_ed25519_public_key', 'label': 'HS Public Key%s' % sfx, 'editable': False})
        files.append({'key': 'tor_log', 'path': '/var/log/tor/log', 'label': 'Tor Log', 'editable': False})
        files.append({'key': 'tor_notices', 'path': '/var/log/tor/notices.log', 'label': 'Tor Notices Log', 'editable': False})
        return files

    # --- Detection ---
    def _find_tor_binary(self):
        results = []
        for p in self.__tor_bin_paths:
            if self._file_exists(p):
                s, _, c = self._run([p, '--version'])
                if c == 0 and 'Tor version' in s: return p, 'direct_path', results
                if os.access(p, os.X_OK): return p, 'direct_path(no_ver)', results
            results.append(('direct:' + p, False))
        for m, cmd in [('which', 'which tor'), ('command_v', 'command -v tor'), ('type_P', 'type -P tor')]:
            s, _, c = self._exec(cmd + ' 2>/dev/null')
            if c == 0 and s: return s.splitlines()[0], m, results
            results.append((m, False))
        s, _, c = self._exec('whereis -b tor 2>/dev/null')
        if c == 0 and s:
            for part in s.split()[1:]:
                if self._file_exists(part): return part, 'whereis', results
        results.append(('whereis', False))
        s, _, c = self._exec('find /usr /snap -name "tor" -type f -executable 2>/dev/null | head -3')
        if c == 0 and s:
            for line in s.splitlines():
                if line.strip():
                    v, _, vc = self._run([line.strip(), '--version'])
                    if vc == 0 and 'Tor version' in v: return line.strip(), 'find', results
        results.append(('find', False))
        s, _, c = self._exec('dpkg -L tor 2>/dev/null | grep -E "bin/tor$"')
        if c == 0 and s:
            for line in s.splitlines():
                if self._file_exists(line.strip()): return line.strip(), 'dpkg_L', results
        results.append(('dpkg_L', False))
        return None, None, results

    def _is_tor_package_installed(self):
        checks = []
        for m, cmd, match in [('dpkg', 'dpkg -s tor 2>/dev/null | grep -i "^Status:"', 'installed'), ('dpkg_query', "dpkg-query -W -f='${Status}' tor 2>/dev/null", 'installed')]:
            s, _, c = self._exec(cmd)
            if c == 0 and s and (not match or match in s.lower()): return True, m, checks
            checks.append((m, False))
        return False, None, checks

    def _is_tor_service_exists(self):
        checks = []
        s, _, c = self._exec('systemctl list-unit-files "tor*" 2>/dev/null')
        if c == 0 and ('tor.service' in s or 'tor@' in s): return True, 'systemd_list', checks
        checks.append(('systemd_list', False))
        for sp in ['/lib/systemd/system/tor.service', '/lib/systemd/system/tor@.service', '/lib/systemd/system/tor@default.service']:
            if self._file_exists(sp): return True, 'file:' + sp, checks
        checks.append(('service_files', False))
        s, _, _ = self._exec('systemctl status tor >/dev/null 2>&1; echo $?')
        if s.strip() != '4': return True, 'systemctl_status', checks
        return False, None, checks

    def _is_tor_running(self):
        for m, cmd in [('pgrep', 'pgrep -x tor'), ('pidof', 'pidof tor')]:
            s, _, c = self._exec(cmd + ' 2>/dev/null')
            if c == 0 and s: return True, s.splitlines()[0].split()[0], m
        return False, '', None

    def _get_tor_version(self, tor_path=None):
        cmd = ('"%s" --version' % tor_path) if tor_path else 'tor --version'
        s, _, c = self._exec(cmd + ' 2>/dev/null')
        if c == 0:
            m = re.search(r'Tor version ([\d.]+)', s)
            if m: return m.group(1)
        return ''

    def _detect_service_name(self):
        if hasattr(self, '_cached_svc_name'):
            return self._cached_svc_name
        for name in ['tor', 'tor@default', 'tor.service']:
            _, _, c = self._exec('systemctl cat %s >/dev/null 2>&1' % name)
            if c == 0:
                self._cached_svc_name = name
                return name
        self._cached_svc_name = 'tor'
        return 'tor'

    # --- PUBLIC API ---
    def quick_check(self, args=None):
        """Fast check: is Tor installed? 2 commands max."""
        # Quick: check binary exists
        s, _, c = self._exec('which tor 2>/dev/null')
        if c == 0 and s.strip():
            return json.dumps({'installed': True, 'distro': self._get_distro()})
        # Quick: check package
        s, _, c = self._exec("dpkg -s tor 2>/dev/null | grep -q 'Status:.*installed'")
        if c == 0:
            return json.dumps({'installed': True, 'distro': self._get_distro()})
        return json.dumps({'installed': False, 'distro': self._get_distro()})

    def check_installed(self, args=None):
        det = {'binary': {'found': False, 'path': '', 'method': '', 'tried': []}, 'package': {'found': False, 'method': '', 'tried': []}, 'service': {'found': False, 'method': '', 'tried': []}, 'running': {'found': False, 'pid': '', 'method': ''}}
        bp, bm, bt_ = self._find_tor_binary()
        if bp: det['binary'] = {'found': True, 'path': bp, 'method': bm, 'tried': []}
        else: det['binary']['tried'] = [t[0] for t in bt_]
        pi, pm, pt = self._is_tor_package_installed()
        if pi: det['package'] = {'found': True, 'method': pm, 'tried': []}
        else: det['package']['tried'] = [t[0] for t in pt]
        se, sm, st = self._is_tor_service_exists()
        if se: det['service'] = {'found': True, 'method': sm, 'tried': []}
        else: det['service']['tried'] = [t[0] for t in st]
        ir, rp, rm = self._is_tor_running()
        if ir: det['running'] = {'found': True, 'pid': rp, 'method': rm}
        installed = det['binary']['found'] or det['package']['found'] or det['service']['found'] or det['running']['found']
        tv = self._get_tor_version(det['binary']['path']) if det['binary']['found'] else (self._get_tor_version() if installed else '')
        return json.dumps({'installed': installed, 'tor_path': det['binary'].get('path', ''), 'tor_version': tv, 'distro': self._get_distro(), 'detection': det, 'torrc_exists': self._file_exists('/etc/tor/torrc'), 'tor_dir_exists': self._dir_exists('/etc/tor'), 'exec_context': self._get_exec_context()})

    def get_status(self, args=None):
        svc = self._detect_service_name()
        s, _, _ = self._exec('systemctl is-active %s 2>/dev/null' % svc)
        is_active = s.strip() == 'active'
        if not is_active:
            r, _, _ = self._is_tor_running()
            is_active = r
        eo, _, _ = self._exec('systemctl is-enabled %s 2>/dev/null' % svc)
        uptime, pid, mem = '', '', ''
        if is_active:
            u, _, _ = self._exec('systemctl show %s --property=ActiveEnterTimestamp --value 2>/dev/null' % svc)
            uptime = u
            p, _, _ = self._exec('systemctl show %s --property=MainPID --value 2>/dev/null' % svc)
            if p and p != '0': pid = p
            else: _, rp, _ = self._is_tor_running(); pid = rp
            if pid:
                mo, _, _ = self._exec('ps -p %s -o rss= 2>/dev/null' % pid)
                if mo:
                    try: mem = str(round(int(mo.strip()) / 1024, 2)) + ' MB'
                    except: pass
        hostnames = []
        for hs_dir in self._get_hidden_service_dirs():
            ok, content, _ = self._read_file(hs_dir + '/hostname')
            if ok and content.strip():
                hostnames.append({'dir': hs_dir, 'hostname': content.strip()})
        return json.dumps({'status': 'active' if is_active else 'inactive', 'enabled': eo.strip() == 'enabled', 'uptime_since': uptime, 'pid': pid, 'memory': mem, 'service_name': svc, 'tor_user': self._get_tor_user(), 'tor_version': self._get_tor_version(), 'hostnames': hostnames})

    def start_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl start %s 2>&1' % svc)
        if c != 0: _, se, c = self._exec('service tor start 2>&1')
        if c != 0: return json.dumps({'status': False, 'msg': 'Failed: ' + se})
        time.sleep(1)
        return json.dumps({'status': True, 'msg': 'Tor started.'})

    def stop_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl stop %s 2>&1' % svc)
        if c != 0: return json.dumps({'status': False, 'msg': 'Failed: ' + se})
        return json.dumps({'status': True, 'msg': 'Tor stopped.'})

    def restart_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc)
        if c != 0: return json.dumps({'status': False, 'msg': 'Failed: ' + se})
        time.sleep(1)
        return json.dumps({'status': True, 'msg': 'Tor restarted.'})

    def reload_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl reload %s 2>&1' % svc)
        if c != 0: _, se, c = self._exec('kill -HUP $(pgrep -x tor) 2>/dev/null')
        if c != 0: return json.dumps({'status': False, 'msg': 'Failed: ' + se})
        return json.dumps({'status': True, 'msg': 'Config reloaded.'})

    def enable_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl enable %s 2>&1' % svc)
        return json.dumps({'status': c == 0, 'msg': 'Enabled.' if c == 0 else 'Failed: ' + se})

    def disable_tor(self, args=None):
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl disable %s 2>&1' % svc)
        return json.dumps({'status': c == 0, 'msg': 'Disabled.' if c == 0 else 'Failed: ' + se})

    # Map codenames to those available in deb.torproject.org
    __tor_repo_codenames = {
        'focal': 'jammy', 'hirsute': 'jammy', 'impish': 'jammy',
        'jammy': 'jammy', 'kinetic': 'jammy', 'lunar': 'jammy', 'mantic': 'jammy',
        'noble': 'noble', 'oracular': 'noble', 'plucky': 'plucky',
        'bullseye': 'bookworm', 'bookworm': 'bookworm', 'trixie': 'trixie', 'sid': 'sid',
    }

    def _get_tor_repo_codename(self):
        distro = self._get_distro()
        cn = distro.get('codename', '')
        return self.__tor_repo_codenames.get(cn, cn)

    def _fix_tor_repo(self):
        """Fix /etc/apt/sources.list.d/tor.list if the codename is no longer available."""
        repo_cn = self._get_tor_repo_codename()
        if not repo_cn:
            return
        keyring = '/usr/share/keyrings/tor-archive-keyring.gpg'
        tl = 'deb [arch=amd64 signed-by=%s] https://deb.torproject.org/torproject.org %s main' % (keyring, repo_cn)
        self._exec('curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --batch --yes --dearmor -o %s 2>/dev/null' % keyring)
        self._write_file('/etc/apt/sources.list.d/tor.list', tl + '\n')

    def install_tor(self, args=None):
        distro = self._get_distro()
        dist, cn, ver = distro['distro'], distro['codename'], distro['version']
        ok = (dist == 'ubuntu' and ver in ('20.04', '22.04', '24.04')) or (dist == 'debian' and ver in ('11', '12'))
        if not ok: return json.dumps({'status': False, 'msg': 'Unsupported: %s %s' % (dist, ver)})
        self._fix_tor_repo()
        repo_cn = self._get_tor_repo_codename()
        tl = 'deb [arch=amd64 signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org %s main' % repo_cn
        cmds = ' && '.join(['apt-get update -y', 'apt-get install -y apt-transport-https gnupg2 curl', 'curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg 2>/dev/null', 'echo "%s" > /etc/apt/sources.list.d/tor.list' % tl, 'apt-get update -y', 'apt-get install -y tor deb.torproject.org-keyring', 'systemctl enable tor'])
        _, se, c = self._exec(cmds, timeout=300)
        if c != 0:
            _, se2, c2 = self._exec('apt-get update -y && apt-get install -y tor && systemctl enable tor', timeout=300)
            if c2 != 0: return json.dumps({'status': False, 'msg': 'Failed: %s | %s' % (se, se2)})
        return json.dumps({'status': True, 'msg': 'Tor installed.'})

    def uninstall_tor(self, args=None):
        cmds = [
            'systemctl stop tor 2>/dev/null',
            'systemctl stop tor@default 2>/dev/null',
            'systemctl disable tor 2>/dev/null',
            'systemctl disable tor@default 2>/dev/null',
            'apt-get purge -y tor tor-geoipdb deb.torproject.org-keyring 2>/dev/null',
            'apt-get autoremove -y 2>/dev/null',
            'rm -f /etc/apt/sources.list.d/tor.list',
            'systemctl daemon-reload',
            'systemctl reset-failed 2>/dev/null',
        ]
        self._exec('; '.join(cmds), timeout=120)
        return json.dumps({'status': True, 'msg': 'Tor uninstalled. /etc/tor/ preserved.'})

    def verify_config(self, args=None):
        tu = self._get_tor_user()
        argv = ['sudo', '-u', tu, 'tor', '--verify-config'] if tu and tu != 'root' else ['tor', '--verify-config']
        so, se, _ = self._run(argv, timeout=15)
        out = so if so else se
        return json.dumps({'status': 'Configuration was valid' in out, 'output': out, 'ran_as': tu})

    def get_file_list(self, args=None):
        result = []
        for f in self._get_important_files():
            exists = self._file_exists(f['path'])
            result.append({'key': f['key'], 'path': f['path'], 'label': f['label'], 'editable': f['editable'], 'exists': exists, 'size': self._file_size(f['path']) if exists else 0})
        return json.dumps(result)

    def read_file(self, args):
        fp, err = self._safe_path(args.get('path', ''))
        if not fp: return json.dumps({'status': False, 'msg': err})
        if not self._file_exists(fp): return json.dumps({'status': False, 'msg': 'Not found: ' + fp})
        ok, content, ib = self._read_file(fp)
        if ok: return json.dumps({'status': True, 'content': content, 'path': fp, 'is_binary': ib})
        return json.dumps({'status': False, 'msg': content})

    def save_file(self, args):
        fp, err = self._safe_path(args.get('path', ''), roots=('/etc/tor',))
        if not fp: return json.dumps({'status': False, 'msg': err or 'Only /etc/tor/ editable.'})
        content = args.get('content', '')
        if not self._file_exists(fp): return json.dumps({'status': False, 'msg': 'Not found: ' + fp})
        bak, berr = self._backup_file(fp)
        if not bak: return json.dumps({'status': False, 'msg': 'Backup failed, nothing written: ' + berr})
        ok, err = self._write_file(fp, content)
        if ok: return json.dumps({'status': True, 'msg': 'Saved. Backup: ' + bak})
        return json.dumps({'status': False, 'msg': 'Failed: ' + err})

    def get_torrc_config(self, args=None):
        directives = self._parse_torrc()
        current = {}
        for key, val in directives:
            if key in current:
                if isinstance(current[key], list): current[key].append(val)
                else: current[key] = [current[key], val]
            else:
                current[key] = val
        options = []
        for opt in self.__torrc_options:
            val = current.get(opt['key'], '')
            if isinstance(val, list): val = '\n'.join(val)
            options.append({'key': opt['key'], 'label': opt['label'], 'desc': opt['desc'], 'default': opt['default'], 'type': opt['type'], 'category': opt['category'], 'options': opt.get('options', []), 'multi': opt.get('multi', False), 'value': val, 'is_set': opt['key'] in current})
        return json.dumps({'status': True, 'config': options, 'tor_user': self._get_tor_user()})

    def save_torrc_config(self, args):
        """Save config changes to torrc, preserving comments and unknown directives."""
        try:
            changes = json.loads(args.get('changes', '{}'))
        except:
            return json.dumps({'status': False, 'msg': 'Invalid JSON.'})
        if not changes:
            return json.dumps({'status': False, 'msg': 'No changes.'})

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})

        # Known option keys for quick lookup
        known_keys = {o['key'] for o in self.__torrc_options}

        lines = content.split('\n')
        new_lines = []
        processed_keys = set()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                new_lines.append(line)
                continue
            parts = stripped.split(None, 1)
            key = parts[0]

            if key in changes:
                if key not in processed_keys:
                    processed_keys.add(key)
                    new_val = changes[key]
                    if new_val == '' or new_val is None:
                        # Remove directive (comment it out)
                        new_lines.append('#' + line)
                    elif '\n' in str(new_val):
                        # Multi-value (like HiddenServicePort)
                        for v in str(new_val).split('\n'):
                            v = v.strip()
                            if v:
                                new_lines.append('%s %s' % (key, v))
                    else:
                        new_lines.append('%s %s' % (key, new_val))
                else:
                    # Duplicate line for same key, skip if we already wrote it
                    if changes[key] == '' or changes[key] is None:
                        new_lines.append('#' + line)
                    # else skip duplicate
            else:
                new_lines.append(line)

        # Add new directives that weren't in the original file
        for key, val in changes.items():
            if key not in processed_keys and val and val.strip():
                if '\n' in str(val):
                    for v in str(val).split('\n'):
                        v = v.strip()
                        if v:
                            new_lines.append('%s %s' % (key, v))
                else:
                    new_lines.append('%s %s' % (key, val))

        new_content = '\n'.join(new_lines)
        ok, err = self._write_file(torrc_path, new_content)
        if ok:
            return json.dumps({'status': True, 'msg': 'torrc saved. Backup: ' + bak + '. Reload Tor to apply.'})
        return json.dumps({'status': False, 'msg': 'Failed: ' + err})

    # --- DOMAIN MANAGEMENT ---
    def list_domains(self, args=None):
        """List all hidden service domains from torrc with their hostnames and key status."""
        directives = self._parse_torrc()
        domains = []
        current_dir = None
        current_ports = []

        for key, val in directives:
            if key == 'HiddenServiceDir':
                # Save previous domain if exists
                if current_dir is not None:
                    domains.append(self._build_domain_info(current_dir, current_ports))
                current_dir = val.rstrip('/')
                current_ports = []
            elif key == 'HiddenServicePort' and current_dir is not None:
                current_ports.append(val)

        # Don't forget the last one
        if current_dir is not None:
            domains.append(self._build_domain_info(current_dir, current_ports))

        return json.dumps({'status': True, 'domains': domains})

    def _build_domain_info(self, hs_dir, ports):
        """Build domain info dict for a hidden service directory."""
        info = {
            'dir': hs_dir,
            'name': hs_dir.rstrip('/').split('/')[-1],
            'ports': ports,
            'hostname': '',
            'has_keys': False,
            'has_hostname': False,
            'dir_exists': self._dir_exists(hs_dir),
            'in_panel': False,
        }
        # Read hostname
        ok, content, _ = self._read_file(hs_dir + '/hostname')
        if ok and content.strip():
            info['hostname'] = content.strip()
            info['has_hostname'] = True
            # Check if this hostname exists in aaPanel's website list
            info['in_panel'] = self._site_exists_in_panel(info['hostname'])
        # Check for keys
        info['has_keys'] = self._file_exists(hs_dir + '/hs_ed25519_secret_key')
        # A service with authorised clients is not reachable without a key, which
        # is worth showing in the list rather than only inside the client dialog.
        auth_dir = self._client_auth_dir(hs_dir)
        count = 0
        if self._dir_exists(auth_dir):
            try:
                count = len([f for f in os.listdir(auth_dir)
                             if f.endswith('.auth')
                             and os.path.isfile(os.path.join(auth_dir, f))
                             and not os.path.islink(os.path.join(auth_dir, f))])
            except Exception:
                count = 0
        info['client_count'] = count
        info['restricted'] = count > 0
        info['circuit_export'] = self._circuit_state(os.path.realpath(hs_dir))['enabled']
        return info

    def _site_exists_in_panel(self, hostname):
        """Check if a hostname already exists in aaPanel's sites database."""
        try:
            sys.path.insert(0, '/www/server/panel/class')
            import public as bt_public
            count = bt_public.M('sites').where('name=?', (hostname,)).count()
            return count > 0
        except:
            return False

    def add_to_panel(self, args):
        """Add a .onion domain as a website in aaPanel."""
        hostname = args.get('hostname', '').strip().lower()
        # endswith('.onion') alone let arbitrary text through into a site path.
        if not self._valid_onion(hostname):
            return json.dumps({'status': False, 'msg': 'Invalid .onion hostname.'})

        # Check if already exists
        if self._site_exists_in_panel(hostname):
            return json.dumps({'status': False, 'msg': 'Site "%s" already exists in aaPanel.' % hostname})

        try:
            sys.path.insert(0, '/www/server/panel/class')
            import panelSite

            # aaPanel internally does 'if key in get' so we need dict-like object
            class SiteArgs(dict):
                def __getattr__(self, key):
                    try: return self[key]
                    except KeyError: raise AttributeError(key)
                def __setattr__(self, key, val):
                    self[key] = val

            get = SiteArgs()
            get.webname = json.dumps({"domain": hostname, "domainlist": [], "count": 0})
            site_path = '/www/wwwroot/' + hostname
            get.path = site_path
            get.ps = 'Tor Hidden Service'
            get.ftp = 'false'
            get.sql = 'false'
            get.codeing = 'utf8'
            get.type = 'PHP'
            get.version = '00'
            get.type_id = '0'
            get.port = '80'
            get.set_ssl = '0'
            get.forceSsl = '0'

            ps = panelSite.panelSite()
            result = ps.AddSite(get)

            if isinstance(result, dict) and (result.get('status') == True or result.get('siteStatus') == True):
                site_path_final = site_path
                os.makedirs(site_path_final, exist_ok=True)
                try:
                    idx_html = '<!DOCTYPE html><html><head><title>Tor Hidden Service</title></head>'
                    idx_html += '<body><h1>Tor Hidden Service Active</h1>'
                    idx_html += '<p>%s</p></body></html>' % hostname
                    with open(site_path_final + '/index.html', 'w') as f:
                        f.write(idx_html)
                except:
                    pass
                return json.dumps({'status': True, 'msg': 'Site "%s" added to aaPanel.' % hostname})
            else:
                err_msg = ''
                if isinstance(result, dict):
                    err_msg = result.get('msg', str(result))
                else:
                    err_msg = str(result)
                return json.dumps({'status': False, 'msg': 'Failed to add site: %s' % err_msg})
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Error: %s' % str(e)})

    def create_domain(self, args):
        """Create a new hidden service domain. Adds block to torrc, creates dir, restarts Tor."""
        name = args.get('svc_name', args.get('name', '')).strip()
        ports = args.get('ports', '').strip()

        if not name:
            return json.dumps({'status': False, 'msg': 'Domain name is required.'})
        # Sanitize name - only alphanumeric, dash, underscore
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            return json.dumps({'status': False, 'msg': 'Name can only contain letters, numbers, dashes, and underscores.'})
        port_lines, perr = self._valid_hs_ports(ports)
        if port_lines is None:
            return json.dumps({'status': False, 'msg': perr})

        # Determine base directory
        data_dir = '/var/lib/tor'
        directives = self._parse_torrc()
        for key, val in directives:
            if key == 'DataDirectory':
                data_dir = val.rstrip('/')
                break

        # `name` is already restricted to [A-Za-z0-9_-], so join cannot escape data_dir.
        data_dir = os.path.realpath(data_dir)
        hs_dir = os.path.join(data_dir, name)

        # Check if already exists in torrc
        for key, val in directives:
            if key == 'HiddenServiceDir' and os.path.realpath(val.rstrip('/')) == hs_dir:
                return json.dumps({'status': False, 'msg': 'Domain "%s" already exists in torrc.' % name})

        # Create directory with correct ownership
        tor_user = self._get_tor_user()
        try:
            os.makedirs(hs_dir, mode=0o700, exist_ok=True)
            os.chmod(hs_dir, 0o700)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot create %s: %s' % (hs_dir, str(e))})
        self._run(['chown', '%s:%s' % (tor_user, tor_user), hs_dir])

        # Build torrc block
        block_lines = []
        block_lines.append('')
        block_lines.append('# Hidden Service: %s' % name)
        block_lines.append('HiddenServiceDir %s' % hs_dir)
        for port_line in port_lines:
            block_lines.append('HiddenServicePort %s' % port_line)

        # Append to torrc
        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})

        new_content = content.rstrip('\n') + '\n' + '\n'.join(block_lines) + '\n'
        ok, err = self._write_file(torrc_path, new_content)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + err})

        # Restart Tor to generate keys
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc, timeout=30)
        if c != 0:
            return json.dumps({'status': True, 'msg': 'Domain added to torrc but Tor restart failed: %s. Try restarting manually.' % se})

        # Wait for hostname to be generated (up to 10 seconds)
        hostname = ''
        for _ in range(10):
            time.sleep(1)
            rok, hcontent, _ = self._read_file(hs_dir + '/hostname')
            if rok and hcontent.strip():
                hostname = hcontent.strip()
                break

        return json.dumps({
            'status': True,
            'msg': 'Domain "%s" created successfully.' % name,
            'hostname': hostname,
            'dir': hs_dir,
            'backup': bak
        })

    def delete_domain(self, args):
        """Remove a hidden service domain. Removes block from torrc, optionally deletes directory."""
        hs_dir, err = self._safe_path(args.get('dir', ''), roots=('/var/lib/tor',))
        delete_files = args.get('delete_files', 'false')

        if not hs_dir:
            return json.dumps({'status': False, 'msg': err or 'No domain directory specified.'})
        # Refuse the data directory itself — this path ends in rmtree().
        if hs_dir == os.path.realpath('/var/lib/tor'):
            return json.dumps({'status': False, 'msg': 'Refusing to operate on the Tor data directory itself.'})

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})

        # Remove the HiddenServiceDir block from torrc
        lines = content.split('\n')
        new_lines = []
        skip_block = False
        removed = False

        for line in lines:
            stripped = line.strip()

            # Check if this is the HiddenServiceDir line we want to remove
            if stripped.startswith('HiddenServiceDir') and not stripped.startswith('#'):
                dir_val = stripped.split(None, 1)[1].rstrip('/') if len(stripped.split(None, 1)) > 1 else ''
                if dir_val and os.path.realpath(dir_val) == hs_dir:
                    skip_block = True
                    removed = True
                    # Also remove comment line above if it's a label comment
                    if new_lines and new_lines[-1].strip().startswith('# Hidden Service:'):
                        new_lines.pop()
                    # Remove blank line above if present
                    if new_lines and not new_lines[-1].strip():
                        new_lines.pop()
                    continue

            # If we're in skip mode, skip HiddenServicePort lines that belong to this block
            if skip_block:
                if stripped.startswith('HiddenServicePort') and not stripped.startswith('#'):
                    continue
                elif stripped.startswith('HiddenServiceVersion') and not stripped.startswith('#'):
                    continue
                else:
                    # We've hit a non-HS directive, stop skipping
                    skip_block = False

            new_lines.append(line)

        if not removed:
            return json.dumps({'status': False, 'msg': 'Domain not found in torrc.'})

        new_content = '\n'.join(new_lines)
        ok, err = self._write_file(torrc_path, new_content)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + err})

        # Delete files if requested. hs_dir is resolved, confirmed under /var/lib/tor
        # and confirmed to be a HiddenServiceDir declared in torrc before we get here.
        if delete_files == 'true' and self._dir_exists(hs_dir):
            try:
                shutil.rmtree(hs_dir)
            except Exception as e:
                return json.dumps({'status': True, 'msg': 'Domain removed from torrc, but deleting %s failed: %s' % (hs_dir, str(e)), 'backup': bak})

        # Restart Tor
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc, timeout=30)

        name = hs_dir.split('/')[-1]
        return json.dumps({
            'status': True,
            'msg': 'Domain "%s" removed. Backup: %s' % (name, bak),
            'backup': bak
        })

    __max_keys_bytes = 2 * 1024 * 1024

    def download_domain_keys(self, args):
        """Package a hidden service's keys as a base64 tar.gz.

        Built in memory on purpose: staging the ed25519 secret key in /tmp under a
        predictable name gave every local account a window to copy it, and whoever
        holds that key owns the .onion identity. Symlinks are skipped so a link
        planted in the directory cannot pull in an unrelated file.
        """
        import base64, io, tarfile
        hs_dir, err = self._safe_path(args.get('dir', ''), roots=('/var/lib/tor',))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err or 'No directory specified.'})
        if hs_dir == os.path.realpath('/var/lib/tor'):
            return json.dumps({'status': False, 'msg': 'Refusing to package the Tor data directory itself.'})
        if not self._dir_exists(hs_dir):
            return json.dumps({'status': False, 'msg': 'Directory does not exist.'})

        name = os.path.basename(hs_dir)
        buf = io.BytesIO()
        try:
            with tarfile.open(fileobj=buf, mode='w:gz') as tar:
                total = 0
                for root, dirs, files in os.walk(hs_dir):
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                    for fn in sorted(files):
                        full = os.path.join(root, fn)
                        if os.path.islink(full) or not os.path.isfile(full):
                            continue
                        total += os.path.getsize(full)
                        if total > self.__max_keys_bytes:
                            raise ValueError('Directory is too large to package.')
                        tar.add(full, arcname=os.path.relpath(full, hs_dir))
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Failed to create archive: ' + str(e)})

        return json.dumps({
            'status': True,
            'filename': '%s_keys.tar.gz' % name,
            'data': base64.b64encode(buf.getvalue()).decode('ascii'),
            'msg': 'Keys packaged for download.'
        })

    # --- KEY RESTORE ---

    __hs_pub_header = b'== ed25519v1-public: type0 =='
    __hs_sec_header = b'== ed25519v1-secret: type0 =='
    __max_restore_bytes = 2 * 1024 * 1024   # decoded archive
    __max_restore_files = 64

    def _onion_from_pubkey(self, pub):
        """Derive the v3 .onion address from a 32-byte ed25519 public key.

        address = base32(pubkey || checksum || version), where
        checksum = SHA3-256(".onion checksum" || pubkey || version)[:2].
        """
        import base64
        ver = b'\x03'
        checksum = hashlib.sha3_256(b'.onion checksum' + pub + ver).digest()[:2]
        return base64.b32encode(pub + checksum + ver).decode('ascii').lower() + '.onion'

    def _parse_hs_key_file(self, raw, header, total_len, key_len):
        """Pull the raw key out of a Tor hs_ed25519_* file, or return None."""
        if len(raw) != total_len or not raw.startswith(header):
            return None
        return raw[total_len - key_len:]

    def _read_backup_archive(self, data_b64):
        """Decode and unpack a key backup into {name: bytes}, or (None, reason).

        The archive arrives from a request, so it is walked member by member
        instead of extractall(): a tar can carry absolute paths, `..` segments,
        symlinks and device nodes, any of which would write outside the target
        directory when extracted as root.
        """
        import base64, io, tarfile
        try:
            raw = base64.b64decode(data_b64 or '', validate=True)
        except Exception:
            return None, 'Invalid base64 payload.'
        if not raw:
            return None, 'Empty upload.'
        if len(raw) > self.__max_restore_bytes:
            return None, 'Backup is too large (max %d KB).' % (self.__max_restore_bytes // 1024)

        files = {}
        total = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
                for m in tar:
                    if m.isdir():
                        continue
                    if not m.isfile():
                        return None, 'Archive contains a %s entry ("%s"); only regular files are accepted.' % (
                            'symlink' if m.issym() or m.islnk() else 'special', m.name)
                    name = m.name
                    while name.startswith('./'):
                        name = name[2:]
                    if (not name or name.startswith('/') or name.startswith('\\')
                            or '\\' in name or '..' in name.split('/')):
                        return None, 'Archive contains an unsafe path: "%s".' % m.name
                    if len(files) >= self.__max_restore_files:
                        return None, 'Archive has too many files.'
                    total += m.size
                    if total > self.__max_restore_bytes:
                        return None, 'Archive expands to more than %d KB.' % (self.__max_restore_bytes // 1024)
                    fh = tar.extractfile(m)
                    if fh is None:
                        return None, 'Cannot read "%s" from the archive.' % m.name
                    files[name] = fh.read()
        except tarfile.TarError as e:
            return None, 'Not a readable .tar.gz: ' + str(e)
        if not files:
            return None, 'Archive is empty.'
        return files, None

    def inspect_domain_backup(self, args):
        """Report what a backup contains without writing anything.

        Lets the panel show which .onion is about to be restored, and whether it
        already exists, before the operator commits to it.
        """
        files, err = self._read_backup_archive(args.get('data', ''))
        if files is None:
            return json.dumps({'status': False, 'msg': err})

        info = {'files': sorted(files.keys()), 'hostname': '', 'derived': '',
                'verified': False, 'warnings': []}

        sec = files.get('hs_ed25519_secret_key')
        if sec is None:
            return json.dumps({'status': False,
                               'msg': 'Backup has no hs_ed25519_secret_key — nothing to restore.'})
        if self._parse_hs_key_file(sec, self.__hs_sec_header, 96, 64) is None:
            return json.dumps({'status': False,
                               'msg': 'hs_ed25519_secret_key is not a valid Tor v3 secret key file.'})

        pub_raw = files.get('hs_ed25519_public_key')
        pub = self._parse_hs_key_file(pub_raw, self.__hs_pub_header, 64, 32) if pub_raw else None
        if pub:
            info['derived'] = self._onion_from_pubkey(pub)
        else:
            info['warnings'].append(
                'No hs_ed25519_public_key in the backup, so the address cannot be verified here. '
                'Tor will derive it from the secret key on start.')

        stated = (files.get('hostname', b'').decode('utf-8', 'replace').strip().lower())
        info['hostname'] = stated
        if stated and info['derived']:
            info['verified'] = (stated == info['derived'])
            if not info['verified']:
                return json.dumps({'status': False,
                                   'msg': 'Backup is inconsistent: hostname says %s but the public key derives %s. '
                                          'Refusing to restore.' % (stated, info['derived'])})
        elif info['derived'] and not stated:
            info['warnings'].append('No hostname file in the backup; %s was derived from the public key.'
                                    % info['derived'])

        addr = info['derived'] or stated
        if addr and not self._valid_onion(addr):
            return json.dumps({'status': False, 'msg': 'Backup does not describe a valid v3 .onion address.'})
        info['address'] = addr
        info['in_torrc'] = ''
        for key, val in self._parse_torrc():
            if key != 'HiddenServiceDir':
                continue
            ok, h, _ = self._read_file(os.path.join(val.rstrip('/'), 'hostname'))
            if ok and h.strip().lower() == addr:
                info['in_torrc'] = val.rstrip('/')
                break
        return json.dumps({'status': True, 'info': info})

    def restore_domain_keys(self, args):
        """Install a hidden service from a key backup and register it in torrc."""
        name = args.get('svc_name', args.get('name', '')).strip()
        if not re.match(r'^[a-zA-Z0-9_-]+$', name or ''):
            return json.dumps({'status': False,
                               'msg': 'Name can only contain letters, numbers, dashes, and underscores.'})
        port_lines, perr = self._valid_hs_ports(args.get('ports', ''))
        if port_lines is None:
            return json.dumps({'status': False, 'msg': perr})

        probe = json.loads(self.inspect_domain_backup(args))
        if not probe.get('status'):
            return json.dumps(probe)
        info = probe['info']
        files = self._read_backup_archive(args.get('data', ''))[0]

        hs_dir = os.path.join(os.path.realpath('/var/lib/tor'), name)
        if self._dir_exists(hs_dir) and os.listdir(hs_dir):
            return json.dumps({'status': False,
                               'msg': 'Directory %s already exists and is not empty. '
                                      'Remove that service first, or restore under a different name.' % hs_dir})
        if info.get('in_torrc'):
            return json.dumps({'status': False,
                               'msg': '%s is already served from %s. Remove it before restoring.'
                                      % (info['address'], info['in_torrc'])})
        for key, val in self._parse_torrc():
            if key == 'HiddenServiceDir' and os.path.realpath(val.rstrip('/')) == hs_dir:
                return json.dumps({'status': False, 'msg': 'Name "%s" is already used in torrc.' % name})

        # Write the keys. Directory 0700 and files 0600 owned by the Tor user, or
        # Tor refuses to load the service.
        tor_user = self._get_tor_user()
        try:
            os.makedirs(hs_dir, mode=0o700, exist_ok=True)
            os.chmod(hs_dir, 0o700)
            for rel in sorted(files):
                dest = os.path.join(hs_dir, *rel.split('/'))
                os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
                with open(dest, 'wb') as f:
                    f.write(files[rel])
                os.chmod(dest, 0o600)
            if 'hostname' not in files and info.get('address'):
                with open(os.path.join(hs_dir, 'hostname'), 'w', encoding='utf-8') as f:
                    f.write(info['address'] + '\n')
                os.chmod(os.path.join(hs_dir, 'hostname'), 0o600)
        except Exception as e:
            shutil.rmtree(hs_dir, ignore_errors=True)
            return json.dumps({'status': False, 'msg': 'Cannot write keys to %s: %s' % (hs_dir, str(e))})
        self._run(['chown', '-R', '%s:%s' % (tor_user, tor_user), hs_dir])

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            shutil.rmtree(hs_dir, ignore_errors=True)
            return json.dumps({'status': False, 'msg': 'Cannot read torrc; keys were not registered.'})
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            shutil.rmtree(hs_dir, ignore_errors=True)
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})
        block = '\n\n# Hidden Service: %s (restored from backup)\nHiddenServiceDir %s' % (name, hs_dir)
        for pl in port_lines:
            block += '\nHiddenServicePort %s' % pl
        ok, err = self._write_file(torrc_path, content.rstrip('\n') + block + '\n')
        if not ok:
            shutil.rmtree(hs_dir, ignore_errors=True)
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + err})

        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc, timeout=30)
        if c != 0:
            return json.dumps({'status': True, 'restored': True, 'hostname': info.get('address', ''),
                               'dir': hs_dir, 'backup': bak,
                               'msg': 'Keys restored and registered, but Tor failed to restart: %s. '
                                      'Check Control -> Verify config.' % se})

        live = ''
        for _ in range(10):
            time.sleep(1)
            rok, h, _ = self._read_file(os.path.join(hs_dir, 'hostname'))
            if rok and h.strip():
                live = h.strip().lower()
                break
        expected = info.get('address', '')
        if live and expected and live != expected:
            return json.dumps({'status': False,
                               'msg': 'Tor published %s but the backup described %s. The service is running — '
                                      'inspect %s before using it.' % (live, expected, hs_dir),
                               'hostname': live, 'dir': hs_dir, 'backup': bak})
        return json.dumps({'status': True, 'restored': True, 'hostname': live or expected,
                           'dir': hs_dir, 'backup': bak,
                           'verified': info.get('verified', False),
                           'warnings': info.get('warnings', []),
                           'msg': 'Restored %s.' % (live or expected or name)})

    # --- V3 CLIENT AUTHORIZATION ---
    #
    # Tor gates a v3 onion behind x25519 keys: the service keeps each client's
    # public key in <HiddenServiceDir>/authorized_clients/<name>.auth, and the
    # client keeps the matching private key in its ClientOnionAuthDir. Visitors
    # without a key cannot even fetch the descriptor.
    #
    # x25519 is implemented here rather than pulled from `cryptography` because
    # this plugin has no Python dependencies at all -- no venv, no pip, nothing
    # to build on a customer box -- and adding one for a single keygen would be
    # a poor trade. The ladder below is RFC 7748 and is checked against that
    # RFC's own test vectors.
    #
    # It is NOT constant-time: Python big-int arithmetic and the branch in the
    # swap both leak timing. That is acceptable strictly because the only scalar
    # it ever processes is a private key this process generated microseconds
    # earlier from os.urandom, against the fixed base point. Do not reuse this
    # for key agreement, or for any scalar that came from a request.

    __P25519 = 2 ** 255 - 19
    __A24 = 121665

    def _x25519_scalarmult(self, k_bytes, u_bytes):
        P, A24 = self.__P25519, self.__A24
        k = bytearray(k_bytes)
        k[0] &= 248
        k[31] &= 127
        k[31] |= 64
        k = int.from_bytes(bytes(k), 'little')
        u = bytearray(u_bytes)
        u[31] &= 127
        x1 = int.from_bytes(bytes(u), 'little')

        x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
        for t in range(254, -1, -1):
            kt = (k >> t) & 1
            swap ^= kt
            if swap:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            swap = kt
            A = (x2 + z2) % P
            AA = A * A % P
            B = (x2 - z2) % P
            BB = B * B % P
            E = (AA - BB) % P
            C = (x3 + z3) % P
            D = (x3 - z3) % P
            DA = D * A % P
            CB = C * B % P
            s = (DA + CB) % P
            d = (DA - CB) % P
            x3 = s * s % P
            z3 = x1 * d % P * d % P
            x2 = AA * BB % P
            z2 = E * (AA + A24 * E % P) % P
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')

    def _x25519_keypair(self):
        """Return (private_bytes, public_bytes), both 32 bytes."""
        import secrets
        priv = bytearray(secrets.token_bytes(32))
        priv[0] &= 248
        priv[31] &= 127
        priv[31] |= 64
        priv = bytes(priv)
        base = b'\x09' + b'\x00' * 31
        return priv, self._x25519_scalarmult(priv, base)

    def _b32(self, raw):
        """Tor writes these keys as unpadded uppercase base32."""
        import base64
        return base64.b32encode(raw).decode('ascii').rstrip('=')

    __client_name_re = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

    def _resolve_hs_dir(self, raw):
        """Contain a hidden-service directory and confirm torrc actually declares it.

        Containment alone would still allow writing into an unrelated directory
        under /var/lib/tor; requiring the declaration means client-auth files can
        only land on a service this panel manages.
        """
        hs_dir, err = self._safe_path(raw, roots=('/var/lib/tor',))
        if not hs_dir:
            return None, err or 'No directory specified.'
        for key, val in self._parse_torrc():
            if key == 'HiddenServiceDir' and os.path.realpath(val.rstrip('/')) == hs_dir:
                return hs_dir, None
        return None, 'No HiddenServiceDir in torrc matches that directory.'

    def _client_auth_dir(self, hs_dir):
        return os.path.join(hs_dir, 'authorized_clients')

    def list_client_auth(self, args):
        """List the client keys authorised for a hidden service.

        Only names are returned. A .auth file holds a public key, but there is no
        reason for it to travel to a browser, so it does not.
        """
        hs_dir, err = self._resolve_hs_dir(args.get('dir', ''))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err})
        auth_dir = self._client_auth_dir(hs_dir)
        clients = []
        malformed = []
        if self._dir_exists(auth_dir):
            try:
                entries = sorted(os.listdir(auth_dir))
            except Exception as e:
                return json.dumps({'status': False, 'msg': 'Cannot list %s: %s' % (auth_dir, str(e))})
            for fn in entries:
                if not fn.endswith('.auth'):
                    continue
                full = os.path.join(auth_dir, fn)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                ok, body, _ = self._read_file(full)
                name = fn[:-len('.auth')]
                if ok and body.strip().startswith('descriptor:x25519:'):
                    clients.append({'name': name, 'file': fn})
                else:
                    malformed.append(fn)
        return json.dumps({'status': True, 'dir': hs_dir, 'auth_dir': auth_dir,
                           'clients': clients, 'malformed': malformed,
                           'restricted': len(clients) > 0})

    def add_client_auth(self, args):
        """Authorise a new client and return its private key exactly once.

        The private key is generated here, handed back in this one response and
        never written to disk or logged -- the panel cannot show it again. Tor
        only needs the public half, so there is nothing to recover if it is lost:
        issue a new client and remove the old one.
        """
        hs_dir, err = self._resolve_hs_dir(args.get('dir', ''))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err})
        name = (args.get('client_name', '') or '').strip()
        if not self.__client_name_re.match(name):
            return json.dumps({'status': False,
                               'msg': 'Client name: letters, numbers, dashes and underscores only (max 64).'})

        ok, host, _ = self._read_file(os.path.join(hs_dir, 'hostname'))
        address = host.strip().lower() if ok else ''
        if not self._valid_onion(address):
            return json.dumps({'status': False,
                               'msg': 'This service has no published .onion hostname yet. '
                                      'Start Tor and wait for the descriptor before adding clients.'})

        auth_dir = self._client_auth_dir(hs_dir)
        dest = os.path.join(auth_dir, name + '.auth')
        if self._file_exists(dest):
            return json.dumps({'status': False, 'msg': 'Client "%s" already exists.' % name})

        existing = json.loads(self.list_client_auth({'dir': hs_dir}))
        first = not existing.get('clients')

        priv, pub = self._x25519_keypair()
        tor_user = self._get_tor_user()
        try:
            os.makedirs(auth_dir, mode=0o700, exist_ok=True)
            os.chmod(auth_dir, 0o700)
            with open(dest, 'w', encoding='utf-8') as f:
                f.write('descriptor:x25519:%s\n' % self._b32(pub))
            os.chmod(dest, 0o600)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot write %s: %s' % (dest, str(e))})
        self._run(['chown', '-R', '%s:%s' % (tor_user, tor_user), auth_dir])

        reloaded = json.loads(self.reload_tor())

        return json.dumps({
            'status': True,
            'name': name,
            'address': address,
            'first_client': first,
            'reloaded': bool(reloaded.get('status')),
            # What the client drops into their ClientOnionAuthDir, as
            # <address-without-.onion>.auth_private
            'auth_private_filename': address[:-len('.onion')] + '.auth_private',
            'auth_private': '%s:descriptor:x25519:%s' % (address[:-len('.onion')], self._b32(priv)),
            'msg': ('Client "%s" authorised. This service is now restricted to authorised clients only.' % name)
                   if first else ('Client "%s" authorised.' % name),
        })

    def remove_client_auth(self, args):
        """Revoke a client key. Removing the last one makes the service public again."""
        hs_dir, err = self._resolve_hs_dir(args.get('dir', ''))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err})
        name = (args.get('client_name', '') or '').strip()
        if not self.__client_name_re.match(name):
            return json.dumps({'status': False, 'msg': 'Invalid client name.'})

        dest = os.path.join(self._client_auth_dir(hs_dir), name + '.auth')
        if os.path.islink(dest) or not self._file_exists(dest):
            return json.dumps({'status': False, 'msg': 'Client "%s" not found.' % name})
        try:
            os.remove(dest)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot remove %s: %s' % (dest, str(e))})

        remaining = json.loads(self.list_client_auth({'dir': hs_dir})).get('clients', [])
        reloaded = json.loads(self.reload_tor())
        msg = 'Client "%s" revoked.' % name
        if not remaining:
            msg += ' No authorised clients remain — this service is public again.'
        return json.dumps({'status': True, 'msg': msg, 'remaining': len(remaining),
                           'public_again': not remaining, 'reloaded': bool(reloaded.get('status'))})

    # --- CIRCUIT EXPORT (per-circuit rate limiting in Onion Guard) ---
    #
    # With HiddenServiceExportCircuitID haproxy, Tor prefixes every connection to
    # the target with a PROXY protocol header whose source address is stable per
    # circuit. Onion Guard reads that to bucket rate limiting per circuit instead
    # of lumping every visitor into one bucket -- on a hidden service they all
    # arrive as 127.0.0.1, so the shared bucket is a switch for shutting the site
    # off rather than a limit.
    #
    # The catch is that the PROXY header is only understood by a listener
    # configured for it, and in nginx proxy_protocol is per-listen and all-or-
    # nothing: a plain HTTP client hitting such a listener is dropped. So the
    # service is repointed at Onion Guard's dedicated circuit port rather than
    # the shared :80, which stays clearnet-capable. This is opt-in per service
    # because applying it restarts Tor, and a Tor restart interrupts every hidden
    # service on the host, not just this one.

    __circuit_comment   = '# tor_manager:circuit-export:original '
    __circuit_directive = 'HiddenServiceExportCircuitID'
    __default_circuit_port = 7779

    def _port_is_listening(self, port, host='127.0.0.1', timeout=2):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False
        finally:
            try: s.close()
            except Exception: pass

    def _hs_block_range(self, lines, hs_dir):
        """Return (start, end) line indexes of hs_dir's block in torrc, or (None, None).

        A service block runs from its HiddenServiceDir line to the next one, so
        edits stay inside the service the operator picked.
        """
        start = None
        for i, line in enumerate(lines):
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            parts = s.split(None, 1)
            if parts[0] != 'HiddenServiceDir':
                continue
            if start is None:
                if len(parts) > 1 and os.path.realpath(parts[1].strip().rstrip('/')) == hs_dir:
                    start = i
            else:
                return start, i
        return (start, len(lines)) if start is not None else (None, None)

    def _circuit_state(self, hs_dir):
        """Report whether hs_dir exports circuit ids, and what it was pointed at."""
        ok, content, _ = self._read_file('/etc/tor/torrc')
        if not ok:
            return {'enabled': False, 'original': '', 'ports': []}
        lines = content.split('\n')
        start, end = self._hs_block_range(lines, hs_dir)
        if start is None:
            return {'enabled': False, 'original': '', 'ports': []}
        block = lines[start:end]
        enabled = any(l.strip().split(None, 1)[0:1] == [self.__circuit_directive]
                      for l in block if l.strip() and not l.strip().startswith('#'))
        original = ''
        for l in block:
            if l.strip().startswith(self.__circuit_comment.strip()):
                original = l.strip()[len(self.__circuit_comment.strip()):].strip()
                break
        ports = [l.strip().split(None, 1)[1] for l in block
                 if l.strip().startswith('HiddenServicePort') and len(l.strip().split(None, 1)) > 1]
        return {'enabled': enabled, 'original': original, 'ports': ports}

    def set_circuit_export(self, args):
        """Turn per-circuit rate limiting on or off for one hidden service."""
        hs_dir, err = self._resolve_hs_dir(args.get('dir', ''))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err})
        enable = str(args.get('enabled', 'true')).strip().lower() in ('1', 'true', 'yes', 'on')
        try:
            cport = int(args.get('circuit_port', self.__default_circuit_port))
        except (TypeError, ValueError):
            cport = self.__default_circuit_port
        if not (1 <= cport <= 65535):
            return json.dumps({'status': False, 'msg': 'Invalid circuit port.'})

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})
        lines = content.split('\n')
        start, end = self._hs_block_range(lines, hs_dir)
        if start is None:
            return json.dumps({'status': False, 'msg': 'Service block not found in torrc.'})

        state = self._circuit_state(hs_dir)
        if state['enabled'] == enable:
            return json.dumps({'status': True, 'unchanged': True, 'enabled': enable,
                               'msg': 'Already %s.' % ('enabled' if enable else 'disabled')})

        if enable and not self._port_is_listening(cport):
            # Repointing at a port nothing serves takes the .onion offline. Onion
            # Guard only writes that listener on nginx (og_circuit.conf), so on an
            # Apache host -- or before the web-server integration has been applied
            # -- this button would otherwise be a one-click outage.
            return json.dumps({'status': False, 'msg':
                'Nothing is listening on 127.0.0.1:%d, so repointing this service there would take '
                '%s offline. Onion Guard writes that listener only for nginx (og_circuit.conf). '
                'Apply the Onion Guard web server integration first, and note that per-circuit rate '
                'limiting needs nginx — on Apache, leave this off.' % (cport, os.path.basename(hs_dir))})

        block = lines[start:end]
        new_block = []
        if enable:
            # Record what each virtual port pointed at, so disabling restores it
            # rather than guessing. Written before any line is rewritten.
            originals = []
            for l in block:
                s = l.strip()
                if s.startswith('HiddenServicePort') and not s.startswith('#'):
                    parts = s.split()
                    if len(parts) >= 3:
                        originals.append('%s=%s' % (parts[1], parts[2]))
                    elif len(parts) == 2:
                        originals.append('%s=' % parts[1])
            if not originals:
                return json.dumps({'status': False,
                                   'msg': 'This service has no HiddenServicePort to repoint.'})
            new_block.append(block[0])
            new_block.append(self.__circuit_comment + ','.join(originals))
            for l in block[1:]:
                s = l.strip()
                if s.startswith('HiddenServicePort') and not s.startswith('#'):
                    parts = s.split()
                    new_block.append('HiddenServicePort %s 127.0.0.1:%d' % (parts[1], cport))
                elif s.startswith(self.__circuit_comment.strip()):
                    continue
                else:
                    new_block.append(l)
            new_block.append('%s haproxy' % self.__circuit_directive)
        else:
            restore = {}
            for pair in (state.get('original') or '').split(','):
                if '=' in pair:
                    vport, target = pair.split('=', 1)
                    restore[vport.strip()] = target.strip()
            for l in block:
                s = l.strip()
                if s.startswith(self.__circuit_comment.strip()):
                    continue
                if s.split(None, 1)[0:1] == [self.__circuit_directive] and not s.startswith('#'):
                    continue
                if s.startswith('HiddenServicePort') and not s.startswith('#'):
                    parts = s.split()
                    target = restore.get(parts[1], '')
                    new_block.append(('HiddenServicePort %s %s' % (parts[1], target)).rstrip())
                    continue
                new_block.append(l)

        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})
        new_content = '\n'.join(lines[:start] + new_block + lines[end:])
        wok, werr = self._write_file(torrc_path, new_content)
        if not wok:
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + werr})

        # A bad torrc stops Tor from starting, which takes every hidden service
        # on this host down, so verify before restarting rather than after.
        vc = json.loads(self.verify_config())
        if not vc.get('status'):
            self._write_file(torrc_path, content)
            return json.dumps({'status': False,
                               'msg': 'Tor rejected the new torrc, so it was rolled back: '
                                      + (vc.get('output', '') or '').strip()[-300:]})

        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc, timeout=30)
        return json.dumps({
            'status': True, 'enabled': enable, 'backup': bak, 'restarted': c == 0,
            'circuit_port': cport,
            'msg': ('Circuit export enabled — this service now reaches Onion Guard on '
                    '127.0.0.1:%d and rate limiting is per circuit.' % cport) if enable
                   else 'Circuit export disabled — original port mapping restored.'
                   + ('' if c == 0 else ' Tor restart failed: %s' % se),
        })

    # --- TOR UPDATE ---
    def check_tor_update(self, args=None):
        s, _, c = self._exec('apt-cache policy tor 2>/dev/null')
        installed, candidate = '', ''
        if c == 0 and s:
            for line in s.splitlines():
                line = line.strip()
                if line.startswith('Installed:'): installed = line.split(':', 1)[1].strip()
                elif line.startswith('Candidate:'): candidate = line.split(':', 1)[1].strip()
        update_available = bool(installed and candidate and installed != candidate and candidate != '(none)')
        return json.dumps({'status': True, 'installed': installed, 'candidate': candidate, 'update_available': update_available, 'tor_version': self._get_tor_version()})

    def update_tor(self, args=None):
        status_file = self._work_path('tor_update.status')
        log_file = self._work_path('tor_update.log')
        svc = self._detect_service_name()
        # Fix the tor repo before updating
        self._fix_tor_repo()
        script = '''#!/bin/bash
exec > "%s" 2>&1
echo "=== Updating Tor repository ==="
apt-get update -y -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/tor.list -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
if [ $? -ne 0 ]; then
    echo "WARNING: Tor repo update had issues, trying full update..."
    apt-get update -y || true
fi
echo ""
echo "=== Installing Tor update ==="
apt-get install --only-upgrade -y tor
if [ $? -ne 0 ]; then
    echo "RESULT:FAIL:apt-get install failed"
    exit 1
fi
echo ""
echo "=== Restarting %s ==="
systemctl restart %s
sleep 2
echo "RESULT:OK"
''' % (log_file, svc, svc)
        script_file = self._work_path('tor_update.sh')
        self._exec('echo \'%s\' > %s && chmod +x %s' % (script.replace("'", "'\\''"), script_file, script_file))
        self._exec('echo "running" > %s' % status_file)
        self._exec('nohup bash %s > /dev/null 2>&1 &' % script_file)
        return json.dumps({'status': True, 'msg': 'Update started in background.', 'background': True})

    def update_tor_status(self, args=None):
        status_file = self._work_path('tor_update.status')
        log_file = self._work_path('tor_update.log')
        s, _, c = self._exec('cat %s 2>/dev/null' % status_file)
        if c != 0 or not s.strip():
            return json.dumps({'status': True, 'running': False, 'done': False})
        log, _, _ = self._exec('cat %s 2>/dev/null' % log_file)
        if 'RESULT:OK' in log:
            self._exec('rm -f %s %s %s' % (status_file, log_file, self._work_path('tor_update.sh')))
            return json.dumps({'status': True, 'running': False, 'done': True, 'success': True, 'msg': 'Tor updated to ' + self._get_tor_version(), 'version': self._get_tor_version(), 'log': log})
        if 'RESULT:FAIL' in log:
            self._exec('rm -f %s %s' % (status_file, self._work_path('tor_update.sh')))
            return json.dumps({'status': True, 'running': False, 'done': True, 'success': False, 'msg': 'Update failed.', 'log': log})
        return json.dumps({'status': True, 'running': True, 'done': False, 'log': log})

    # --- MKP224O VANITY ADDRESSES ---
    def check_mkp224o(self, args=None):
        for path in ['/opt/mkp224o/mkp224o', '/usr/local/bin/mkp224o']:
            if self._file_exists(path):
                return json.dumps({'status': True, 'installed': True, 'path': path})
        return json.dumps({'status': True, 'installed': False, 'path': ''})

    def install_mkp224o(self, args=None):
        cmds = ['apt-get install -y gcc libsodium-dev make autoconf git 2>&1']
        cmds.append('rm -rf /opt/mkp224o && git clone https://github.com/cathugger/mkp224o /opt/mkp224o 2>&1')
        cmds.append('cd /opt/mkp224o && ./autogen.sh 2>&1')
        # Detect architecture for optimal build
        arch, _, _ = self._exec('uname -m')
        if 'x86_64' in arch or 'amd64' in arch:
            cmds.append('cd /opt/mkp224o && ./configure --enable-amd64-51-30k 2>&1')
        elif 'aarch64' in arch:
            cmds.append('cd /opt/mkp224o && ./configure 2>&1')
        else:
            cmds.append('cd /opt/mkp224o && ./configure 2>&1')
        cmds.append('cd /opt/mkp224o && make -j$(nproc) 2>&1')
        for cmd in cmds:
            _, se, c = self._exec(cmd, timeout=300)
            if c != 0:
                return json.dumps({'status': False, 'msg': 'Failed at: %s\nError: %s' % (cmd.split('2>&1')[0].strip(), se)})
        if not self._file_exists('/opt/mkp224o/mkp224o'):
            return json.dumps({'status': False, 'msg': 'Build completed but binary not found.'})
        return json.dumps({'status': True, 'msg': 'mkp224o installed successfully.', 'path': '/opt/mkp224o/mkp224o'})

    def uninstall_mkp224o(self, args=None):
        self._exec('pkill -f "mkp224o" 2>/dev/null')
        self._exec('rm -rf /opt/mkp224o 2>/dev/null')
        self._exec('rm -rf %s 2>/dev/null' % os.path.join(self._work_dir(), 'tor_vanity_*'))
        self._purge_legacy_tmp()
        return json.dumps({'status': True, 'msg': 'mkp224o removed.'})

    def benchmark_mkp224o(self, args=None):
        mkp_path = '/opt/mkp224o/mkp224o'
        if not self._file_exists(mkp_path):
            return json.dumps({'status': False, 'msg': 'mkp224o not installed.'})
        # Run ~5 sec benchmark with long prefix that won't match
        out_dir = self._work_path('mkp224o_bench_%d' % int(time.time()))
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        s, se, _ = self._run(['timeout', '6', mkp_path, '-B', '-S', '3', '-n', '0',
                              '-d', out_dir, 'zzzzzzzzzz'], timeout=12)
        shutil.rmtree(out_dir, ignore_errors=True)
        rate = 0
        for line in (s + '\n' + se).splitlines():
            if 'calc/sec' in line:
                m = re.search(r'calc/sec[:\s]*([\d.]+)', line)
                if m:
                    try: rate = max(rate, float(m.group(1)))
                    except: pass
        cpu_info, _, _ = self._exec("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
        cores, _, _ = self._exec('nproc')
        estimates = []
        for n in range(1, 9):
            avg_attempts = (32 ** n) / 2.0
            if rate > 0:
                secs = avg_attempts / rate
                estimates.append({'chars': n, 'seconds': secs, 'display': self._fmt_time(secs)})
            else:
                estimates.append({'chars': n, 'seconds': -1, 'display': 'Unknown'})
        return json.dumps({
            'status': True, 'rate': rate,
            'rate_display': self._fmt_rate(rate),
            'cpu': (cpu_info.strip() if cpu_info else 'Unknown'),
            'cores': (cores.strip() if cores else '1'),
            'estimates': estimates
        })

    def _fmt_time(self, s):
        if s < 1: return '< 1 second'
        if s < 60: return '%d seconds' % int(s)
        if s < 3600: return '%d minutes' % int(s / 60)
        if s < 86400: return '%.1f hours' % (s / 3600)
        if s < 2592000: return '%.1f days' % (s / 86400)
        if s < 31536000: return '%.1f months' % (s / 2592000)
        return '%.1f years' % (s / 31536000)

    def _fmt_rate(self, r):
        if r >= 1e6: return '%.1fM keys/sec' % (r / 1e6)
        if r >= 1e3: return '%.1fK keys/sec' % (r / 1e3)
        return '%.0f keys/sec' % r

    __vanity_root   = '/var/lib/tor_manager'
    __legacy_vanity_root = '/tmp'
    __vanity_job_re = re.compile(r'^\d{1,20}$')

    def _vanity_paths(self, job_id):
        """Return (out_dir, log_file, pid_file) for a job id, or None if malformed.

        job_id arrives from the request, so it is pinned to digits before it is
        used to build any path.
        """
        job_id = (job_id or '').strip()
        if not self.__vanity_job_re.match(job_id):
            return None
        base = os.path.join(self.__vanity_root, 'tor_vanity_' + job_id)
        return base, base + '.log', base + '.pid'

    def _safe_vanity_keys_dir(self, raw):
        """Validate a mkp224o output directory before copying keys out of it.

        The panel echoes this path back from check_vanity_status, but the request
        can carry anything, so the expected shape is re-checked:
        <root>/tor_vanity_<digits>/<addr>.onion
        """
        path, err = self._safe_path(raw, roots=(self.__vanity_root,))
        if not path:
            return None, err
        parent = os.path.dirname(path)
        pname = os.path.basename(parent)
        if (not pname.startswith('tor_vanity_')
                or not self.__vanity_job_re.match(pname[len('tor_vanity_'):])
                or os.path.dirname(parent) != os.path.realpath(self.__vanity_root)
                or not self._valid_onion(os.path.basename(path))):
            return None, 'Not a vanity key directory.'
        if not self._dir_exists(path):
            return None, 'Keys directory not found.'
        return path, None

    def start_vanity_gen(self, args):
        prefix = args.get('prefix', '').strip().lower()
        if not prefix:
            return json.dumps({'status': False, 'msg': 'Prefix is required.'})
        if not re.match(r'^[a-z2-7]+$', prefix):
            return json.dumps({'status': False, 'msg': 'Only a-z and 2-7 allowed in .onion addresses.'})
        if len(prefix) > 10:
            return json.dumps({'status': False, 'msg': 'Maximum 10 characters.'})
        mkp_path = '/opt/mkp224o/mkp224o'
        if not self._file_exists(mkp_path):
            return json.dumps({'status': False, 'msg': 'mkp224o not installed.'})
        # Kill existing and clean up
        self._exec('pkill -f "mkp224o.*-d .*tor_vanity" 2>/dev/null')
        time.sleep(0.5)
        job_id = str(int(time.time()))
        out_dir, log_file, pid_file = self._vanity_paths(job_id)
        self._exec('rm -rf %s 2>/dev/null' % os.path.join(self._work_dir(), 'tor_vanity_*'))
        self._purge_legacy_tmp()
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        cores, _, _ = self._exec('nproc')
        try: threads = max(1, int(cores.strip()) - 1)
        except: threads = 1
        try:
            with open(log_file, 'wb') as logf:
                proc = subprocess.Popen(
                    [mkp_path, '-B', '-n', '1', '-t', str(threads), '-d', out_dir, '-S', '5', prefix],
                    stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    env=self._env(), start_new_session=True)
            self._write_file(pid_file, str(proc.pid))
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Could not start mkp224o: ' + str(e)})
        return json.dumps({'status': True, 'job_id': job_id, 'prefix': prefix, 'threads': threads})

    def check_vanity_status(self, args):
        paths = self._vanity_paths(args.get('job_id', ''))
        if not paths: return json.dumps({'status': False, 'msg': 'No valid job ID.'})
        out_dir, log_file, pid_file = paths
        # The pid file lives in a world-writable directory, so treat its contents
        # as untrusted: only a plain number is accepted before it reaches kill().
        running = False
        ok, pid_raw, _ = self._read_file(pid_file) if self._file_exists(pid_file) else (False, '', False)
        if ok and re.match(r'^\d{1,10}$', pid_raw.strip()):
            try:
                os.kill(int(pid_raw.strip()), 0)
                running = True
            except Exception:
                running = False
        # Check for found .onion directory
        found_dir, found_hostname = '', ''
        try:
            for entry in sorted(os.listdir(out_dir)):
                cand = os.path.join(out_dir, entry)
                if self._valid_onion(entry) and os.path.isdir(cand) and not os.path.islink(cand):
                    found_dir = cand
                    break
        except Exception:
            pass
        if found_dir:
            hok, h, _ = self._read_file(os.path.join(found_dir, 'hostname'))
            if hok and h.strip(): found_hostname = h.strip()
        # Parse latest stats
        rate = ''
        if self._file_exists(log_file):
            lok, log_text, _ = self._read_file(log_file)
            s = '\n'.join(log_text.splitlines()[-5:]) if lok else ''
            for line in (s or '').splitlines():
                if 'calc/sec' in line:
                    m = re.search(r'calc/sec[:\s]*([\d.]+)', line)
                    if m:
                        try: rate = self._fmt_rate(float(m.group(1)))
                        except: pass
        if found_hostname:
            return json.dumps({'status': True, 'state': 'found', 'hostname': found_hostname, 'keys_dir': found_dir, 'rate': rate, 'running': False})
        elif running:
            return json.dumps({'status': True, 'state': 'running', 'rate': rate, 'running': True})
        else:
            return json.dumps({'status': True, 'state': 'stopped', 'rate': rate, 'running': False})

    def cancel_vanity_gen(self, args=None):
        self._exec('pkill -f "mkp224o.*-d .*tor_vanity" 2>/dev/null')
        self._exec('rm -rf %s 2>/dev/null' % os.path.join(self._work_dir(), 'tor_vanity_*'))
        self._purge_legacy_tmp()
        return json.dumps({'status': True, 'msg': 'Cancelled.'})

    def apply_vanity_keys(self, args):
        keys_dir = args.get('keys_dir', '').strip()
        name = args.get('svc_name', args.get('name', '')).strip()
        ports = args.get('ports', '').strip()
        if not keys_dir or not name or not ports:
            return json.dumps({'status': False, 'msg': 'Missing parameters.'})
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            return json.dumps({'status': False, 'msg': 'Invalid name.'})
        keys_dir, kerr = self._safe_vanity_keys_dir(keys_dir)
        if not keys_dir:
            return json.dumps({'status': False, 'msg': kerr})
        port_lines, perr = self._valid_hs_ports(ports)
        if port_lines is None:
            return json.dumps({'status': False, 'msg': perr})
        hs_dir = os.path.join(os.path.realpath('/var/lib/tor'), name)
        for key, val in self._parse_torrc():
            if key == 'HiddenServiceDir' and os.path.realpath(val.rstrip('/')) == hs_dir:
                return json.dumps({'status': False, 'msg': 'Domain "%s" already exists.' % name})
        tor_user = self._get_tor_user()
        try:
            os.makedirs(hs_dir, mode=0o700, exist_ok=True)
            for entry in sorted(os.listdir(keys_dir)):
                src = os.path.join(keys_dir, entry)
                if os.path.islink(src) or not os.path.isfile(src):
                    continue
                dst = os.path.join(hs_dir, entry)
                shutil.copy2(src, dst)
                os.chmod(dst, 0o600)
            os.chmod(hs_dir, 0o700)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot install keys into %s: %s' % (hs_dir, str(e))})
        self._run(['chown', '-R', '%s:%s' % (tor_user, tor_user), hs_dir])
        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok: return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})
        block = '\n\n# Hidden Service: %s (custom vanity)\nHiddenServiceDir %s' % (name, hs_dir)
        for pl in port_lines:
            block += '\nHiddenServicePort %s' % pl
        ok, err = self._write_file(torrc_path, content.rstrip('\n') + block + '\n')
        if not ok: return json.dumps({'status': False, 'msg': 'Failed: ' + err})
        svc = self._detect_service_name()
        self._exec('systemctl restart %s 2>&1' % svc, timeout=30)
        hostname = ''
        rok, hc, _ = self._read_file(hs_dir + '/hostname')
        if rok and hc.strip(): hostname = hc.strip()
        self._exec('rm -rf %s 2>/dev/null' % os.path.join(self._work_dir(), 'tor_vanity_*'))
        self._purge_legacy_tmp()
        return json.dumps({'status': True, 'msg': 'Custom domain created.', 'hostname': hostname, 'dir': hs_dir, 'backup': bak})

    def get_logs(self, args=None):
        lines = 100
        if args and args.get('lines'):
            try: lines = min(max(int(args['lines']), 10), 1000)
            except: pass
        svc = self._detect_service_name()
        for u in [svc, 'tor', 'tor@default']:
            so, _, c = self._exec('journalctl -u %s --no-pager -n %d 2>/dev/null' % (u, lines))
            if c == 0 and so and 'No entries' not in so and len(so) > 20:
                return json.dumps({'status': True, 'logs': so, 'source': 'journalctl (%s)' % u})
        for lp in ['/var/log/tor/log', '/var/log/tor/notices.log']:
            if self._file_exists(lp):
                so, _, _ = self._exec('tail -n %d "%s"' % (lines, lp))
                if so: return json.dumps({'status': True, 'logs': so, 'source': lp})
        return json.dumps({'status': False, 'logs': 'No Tor logs found.', 'source': ''})

    # --- WEB SERVER SWITCH ---
    __panel_db = '/www/server/panel/data/default.db'

    def _panel_webserver(self):
        """What aaPanel's config row claims is the web server.

        Read with the sqlite3 module, not the sqlite3 CLI: the CLI is not part of
        an aaPanel install and is missing on plenty of hosts, in which case the
        old shell query returned an empty string and the tab showed nothing.
        """
        try:
            import sqlite3
            con = sqlite3.connect('file:%s?mode=ro' % self.__panel_db, uri=True, timeout=5)
            try:
                row = con.execute('SELECT webserver FROM config WHERE id=1').fetchone()
            finally:
                con.close()
            if row and row[0]:
                return str(row[0]).strip()
        except Exception:
            pass
        try:
            sys.path.insert(0, '/www/server/panel/class')
            import db
            row = db.Sql().table('config').where('id=?', (1,)).field('webserver').find()
            if row and row.get('webserver'):
                return str(row['webserver']).strip()
        except Exception:
            pass
        return ''

    def _running_webserver(self):
        """What is actually serving, which is not always what the panel believes.

        Ground truth is who holds the listening socket. Deliberately not `pgrep -f`:
        the pattern would appear in the command line of the shell running the
        probe, so it matches itself and reports a server that is not there.
        """
        out, _, _ = self._run(['ss', '-tlnp'])
        owners = ''
        for line in (out or '').splitlines():
            if ':80 ' in line or ':443 ' in line:
                owners += line.lower()
        has_apache = 'httpd' in owners or 'apache' in owners
        has_nginx = 'nginx' in owners
        if has_apache and not has_nginx:
            return 'apache'
        if has_nginx and not has_apache:
            return 'nginx'
        if has_apache and has_nginx:
            return ''            # genuinely ambiguous; do not guess
        # Nothing listening (server stopped): fall back to what is installed.
        nginx_bin = self._file_exists('/www/server/nginx/sbin/nginx')
        apache_bin = self._file_exists('/www/server/apache/bin/httpd')
        if apache_bin and not nginx_bin:
            return 'apache'
        if nginx_bin and not apache_bin:
            return 'nginx'
        return ''

    def sync_panel_webserver(self, args=None):
        """Correct aaPanel's config row to match the server that is actually running.

        Offered as an explicit action rather than done silently: this writes to the
        panel's own database, and other parts of aaPanel read that row.
        """
        detected = self._running_webserver()
        if detected not in ('nginx', 'apache'):
            return json.dumps({'status': False,
                               'msg': 'Could not determine the running web server, so the panel '
                                      'config was left alone.'})
        stored = self._panel_webserver()
        if stored == detected:
            return json.dumps({'status': True, 'unchanged': True, 'current': detected,
                               'msg': 'Panel config already says %s.' % detected})
        try:
            import sqlite3
            con = sqlite3.connect(self.__panel_db, timeout=10)
            try:
                con.execute('UPDATE config SET webserver=? WHERE id=1', (detected,))
                con.commit()
            finally:
                con.close()
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Could not update panel config: ' + str(e)})
        return json.dumps({'status': True, 'current': detected, 'previous': stored,
                           'msg': 'Panel config corrected from "%s" to "%s".'
                                  % (stored or '(empty)', detected)})

    def get_webserver_status(self, args=None):
        """Report the running web server, and whether the panel agrees with it."""
        panel_says = self._panel_webserver()
        detected = self._running_webserver()
        # Reality wins. Trusting the stored row alone reported nginx on a host
        # where nginx was not installed and Apache was serving every request.
        current = detected or panel_says

        # Check installed
        nginx_installed = self._file_exists('/www/server/nginx/sbin/nginx')
        apache_installed = self._file_exists('/www/server/apache/bin/httpd')

        # Get versions
        nginx_ver = ''
        if nginx_installed:
            v, _, _ = self._exec('/www/server/nginx/sbin/nginx -v 2>&1')
            m = re.search(r'nginx/([\d.]+)', v)
            if m: nginx_ver = m.group(1)

        apache_ver = ''
        if apache_installed:
            v, _, _ = self._exec('/www/server/apache/bin/httpd -v 2>&1')
            m = re.search(r'Apache/([\d.]+)', v)
            if m: apache_ver = m.group(1)

        # Check phpmyadmin
        pma_installed = self._dir_exists('/www/server/phpmyadmin/pma') or self._dir_exists('/www/server/phpmyadmin')

        # Check if a switch task is running
        switching = self._file_exists(self._work_path('webserver_switch.status'))

        return json.dumps({
            'status': True,
            'current': current,
            'detected': detected,
            'panel_config': panel_says,
            # The panel's row drives other aaPanel behaviour, so a disagreement is
            # worth surfacing rather than quietly papering over.
            'mismatch': bool(detected and panel_says and detected != panel_says),
            'nginx': {'installed': nginx_installed, 'version': nginx_ver},
            'apache': {'installed': apache_installed, 'version': apache_ver},
            'phpmyadmin': {'installed': pma_installed},
            'switching': switching,
        })

    def switch_webserver(self, args):
        """Switch web server between nginx and apache. Runs in background."""
        target = args.get('target', '').strip().lower()
        if target not in ('nginx', 'apache'):
            return json.dumps({'status': False, 'msg': 'Target must be "nginx" or "apache".'})

        # Get current
        current = self._running_webserver() or self._panel_webserver()
        if current == target:
            return json.dumps({'status': False, 'msg': '%s is already the active web server.' % target.title()})

        # Check if already switching
        if self._file_exists(self._work_path('webserver_switch.status')):
            return json.dumps({'status': False, 'msg': 'A switch is already in progress.'})

        # Build the switch script
        status_file = self._work_path('webserver_switch.status')
        log_file = self._work_path('webserver_switch.log')
        script = self._build_switch_script(current, target, status_file, log_file)

        script_file = self._work_path('webserver_switch.sh')
        ok, err = self._write_file(script_file, script)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Failed to create script: ' + err})
        os.chmod(script_file, 0o700)
        self._exec('echo "running" > %s' % status_file)
        self._exec('echo "" > %s' % log_file)
        self._exec('nohup bash %s > /dev/null 2>&1 &' % script_file)

        return json.dumps({
            'status': True,
            'msg': 'Switching from %s to %s. This may take several minutes.' % (current, target),
            'background': True,
        })

    def _build_switch_script(self, current, target, status_file, log_file):
        """Build a shell script to switch web servers via aaPanel's install system."""
        # Determine what to install/remove
        # aaPanel uses install_soft.sh: bash install_soft.sh 3 install <name> <version>
        # type 3 = Ubuntu/Debian
        script = '''#!/bin/bash
exec > "%(log)s" 2>&1
echo "=== Web Server Switch: %(current)s -> %(target)s ==="
echo "Started: $(date)"
echo ""

cd /www/server/panel/install

# Step 1: Install target web server
echo "STEP 1: Installing %(target)s..."
if [ "%(target)s" = "nginx" ]; then
    bash install_soft.sh 3 install nginx 1.27
    if [ $? -ne 0 ]; then
        echo "RESULT:FAIL:Failed to install nginx"
        rm -f "%(status)s"
        exit 1
    fi
elif [ "%(target)s" = "apache" ]; then
    bash install_soft.sh 3 install apache 2.4
    if [ $? -ne 0 ]; then
        echo "RESULT:FAIL:Failed to install apache"
        rm -f "%(status)s"
        exit 1
    fi
fi
echo "%(target)s installed."
echo ""

# Step 2: Update aaPanel config to use new web server
echo "STEP 2: Updating aaPanel config..."
# Via the sqlite3 module, not the CLI: the CLI is not part of an aaPanel install
# and is absent on plenty of hosts, where this UPDATE would silently do nothing.
python3 -c "import sqlite3,sys;c=sqlite3.connect('/www/server/panel/data/default.db',timeout=10);c.execute('UPDATE config SET webserver=? WHERE id=1',(sys.argv[1],));c.commit();c.close()" '%(target)s'
if [ $? -ne 0 ]; then
    echo "RESULT:FAIL:Could not update the panel config row"
    rm -f "%(status)s"
    exit 1
fi
echo "Config updated to %(target)s."
echo ""

# Step 3: Reinstall phpMyAdmin for the new web server
echo "STEP 3: Reinstalling phpMyAdmin..."
bash install_soft.sh 3 install phpmyadmin 5.2
echo "phpMyAdmin reinstalled."
echo ""

# Step 4: Stop old web server completely
echo "STEP 4: Stopping and disabling %(current)s..."
if [ "%(current)s" = "nginx" ]; then
    /etc/init.d/nginx stop 2>/dev/null
    systemctl stop nginx 2>/dev/null
    systemctl disable nginx 2>/dev/null
    # Kill site nginx processes only (not panel webserver)
    pkill -9 -f "server/nginx/sbin/nginx" 2>/dev/null
    # Kill any stuck init.d nginx scripts
    pkill -9 -f "init.d/nginx" 2>/dev/null
elif [ "%(current)s" = "apache" ]; then
    /etc/init.d/httpd stop 2>/dev/null
    systemctl stop httpd 2>/dev/null
    systemctl stop apache2 2>/dev/null
    systemctl disable httpd 2>/dev/null
    systemctl disable apache2 2>/dev/null
    pkill -9 httpd 2>/dev/null
fi
sleep 2
echo "%(current)s stopped and disabled."
echo ""

# Step 5: Start new web server and restart aaPanel
echo "STEP 5: Starting %(target)s and restarting panel..."
if [ "%(target)s" = "nginx" ]; then
    systemctl enable nginx 2>/dev/null
    /etc/init.d/nginx start 2>/dev/null || systemctl start nginx 2>/dev/null
elif [ "%(target)s" = "apache" ]; then
    systemctl enable httpd 2>/dev/null || systemctl enable apache2 2>/dev/null
    /etc/init.d/httpd start 2>/dev/null || systemctl start apache2 2>/dev/null
fi
sleep 2
bt restart 2>/dev/null
sleep 5
echo ""

echo "STEP 6: Verifying..."
ACTIVE_WS=$(python3 -c "import sqlite3;c=sqlite3.connect('/www/server/panel/data/default.db',timeout=10);print((c.execute('SELECT webserver FROM config WHERE id=1').fetchone() or [''])[0]);c.close()")
echo "Active web server in DB: $ACTIVE_WS"

if [ "$ACTIVE_WS" = "%(target)s" ]; then
    echo ""
    echo "RESULT:OK"
else
    echo ""
    echo "RESULT:FAIL:Config mismatch after switch"
fi

rm -f "%(status)s"
echo ""
echo "Completed: $(date)"
''' % {'current': current, 'target': target, 'status': status_file, 'log': log_file}
        return script

    def switch_webserver_status(self, args=None):
        """Check the status of a running web server switch."""
        status_file = self._work_path('webserver_switch.status')
        log_file = self._work_path('webserver_switch.log')

        s, _, c = self._exec('cat %s 2>/dev/null' % status_file)
        if c != 0 or not s.strip():
            # Not running, check if log exists with result
            log, _, lc = self._exec('cat %s 2>/dev/null' % log_file)
            if lc == 0 and log:
                if 'RESULT:OK' in log:
                    self._exec('rm -f %s' % log_file)
                    return json.dumps({'status': True, 'running': False, 'done': True, 'success': True, 'msg': 'Switch completed.', 'log': log})
                elif 'RESULT:FAIL' in log:
                    m = re.search(r'RESULT:FAIL:(.*)', log)
                    err = m.group(1) if m else 'Unknown error'
                    return json.dumps({'status': True, 'running': False, 'done': True, 'success': False, 'msg': err, 'log': log})
            return json.dumps({'status': True, 'running': False, 'done': False})

        log, _, _ = self._exec('cat %s 2>/dev/null' % log_file)
        # Extract current step
        step = ''
        for line in (log or '').splitlines():
            if line.startswith('STEP'):
                step = line

        return json.dumps({'status': True, 'running': True, 'done': False, 'step': step, 'log': log})

    # --- ONIONBALANCE (high availability for a .onion address) ---
    #
    # OnionBalance publishes one descriptor for a "frontend" address that points
    # at the introduction points of several backend hidden services. Clients then
    # reach a backend directly; the daemon never carries traffic, so it is not a
    # bottleneck and does not have to sit near the backends.
    #
    # It is genuinely useful only when the backends live on different hosts. On a
    # single server it adds moving parts without removing the single point of
    # failure, so nothing here is on by default and the UI says that rather than
    # presenting it as a free win.
    #
    # Installed on demand into its own venv, the same way mkp224o is compiled on
    # demand: this plugin has no Python dependencies and should not gain one for
    # a feature most installs will never switch on.

    __ob_dir          = '/opt/onionbalance'
    __ob_venv         = '/opt/onionbalance/venv'
    __ob_bin          = '/opt/onionbalance/venv/bin/onionbalance'
    __ob_config       = '/opt/onionbalance/config.yaml'
    __ob_key          = '/opt/onionbalance/frontend.key'
    __ob_service      = '/etc/systemd/system/onionbalance.service'
    __ob_log          = '/var/log/onionbalance.log'
    __ob_install_log  = '/opt/onionbalance/install.log'
    __ob_install_flag = '/opt/onionbalance/.installing'
    __ob_control_port = 9051

    def _ob_installed(self):
        return self._file_exists(self.__ob_bin)

    def _ob_version(self):
        if not self._ob_installed():
            return ''
        o, e, c = self._run([self.__ob_bin, '--version'], timeout=20)
        out = (o or e or '').strip()
        m = re.search(r'(\d+\.\d+[\w.]*)', out)
        return m.group(1) if m else out[:40]

    def _ob_read_config(self):
        """Parse back the config this plugin wrote.

        Deliberately regexes rather than a YAML parser: the file is generated
        here from validated values, and pulling in PyYAML would cost the plugin
        its zero-dependency property for no gain.
        """
        ok, content, _ = self._read_file(self.__ob_config)
        if not ok:
            return {'key': '', 'instances': []}
        key = ''
        m = re.search(r'^\s*-?\s*key:\s*(\S+)\s*$', content, re.MULTILINE)
        if m:
            key = m.group(1)
        instances = []
        for line in content.splitlines():
            m = re.match(r'^-\s*address:\s*([a-z2-7]{56}\.onion)$', line.strip(), re.IGNORECASE)
            if m:
                instances.append(m.group(1).lower())
        return {'key': key, 'instances': instances}

    def _ob_frontend_address(self):
        """The balanced address, derived from the frontend key's public half."""
        pub_path = self.__ob_key + '.pub'
        if self._file_exists(pub_path):
            try:
                with open(pub_path, 'rb') as f:
                    pub = self._parse_hs_key_file(f.read(), self.__hs_pub_header, 64, 32)
                if pub:
                    return self._onion_from_pubkey(pub)
            except Exception:
                pass
        ok, addr, _ = self._read_file(self.__ob_key + '.address')
        return addr.strip().lower() if ok else ''

    def _tor_control_state(self):
        """OnionBalance drives Tor over the control port, so it has to be open.

        Reported rather than switched on silently: opening a control port is a
        real change, and one bound anywhere but loopback hands complete control
        of Tor to anyone who can reach it.
        """
        state = {'control_port': '', 'cookie_auth': False, 'listening': False, 'exposed': False}
        for key, val in self._parse_torrc():
            if key == 'ControlPort':
                v = val.strip()
                state['control_port'] = v
                if ':' in v:
                    host = v.rsplit(':', 1)[0]
                    if host not in ('127.0.0.1', 'localhost', '[::1]'):
                        state['exposed'] = True
            elif key == 'CookieAuthentication':
                state['cookie_auth'] = val.strip() == '1'
        port = self.__ob_control_port
        if state['control_port']:
            try:
                port = int(state['control_port'].rsplit(':', 1)[-1])
            except ValueError:
                pass
        state['listening'] = self._port_is_listening(port)
        return state

    def enable_tor_control_port(self, args=None):
        """Add a loopback-only control port with cookie authentication."""
        state = self._tor_control_state()
        if state['exposed']:
            return json.dumps({'status': False, 'msg':
                'torrc already has "ControlPort %s", which is not loopback-only. Anyone able to reach '
                'that port controls Tor completely, including reading hidden service keys. Fix that by '
                'hand before enabling OnionBalance.' % state['control_port']})
        if state['control_port'] and state['cookie_auth']:
            return json.dumps({'status': True, 'unchanged': True,
                               'msg': 'Control port already configured on %s.' % state['control_port']})

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})
        block = ['', '# Added by Tor Manager for OnionBalance.',
                 '# Loopback only on purpose: a reachable control port is full control of Tor.']
        if not state['control_port']:
            block.append('ControlPort 127.0.0.1:%d' % self.__ob_control_port)
        if not state['cookie_auth']:
            block.append('CookieAuthentication 1')
        bak, berr = self._backup_file(torrc_path)
        if not bak:
            return json.dumps({'status': False, 'msg': 'Backup failed, torrc not modified: ' + berr})
        ok, err = self._write_file(torrc_path, content.rstrip('\n') + '\n' + '\n'.join(block) + '\n')
        if not ok:
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + err})
        vc = json.loads(self.verify_config())
        if not vc.get('status'):
            self._write_file(torrc_path, content)
            return json.dumps({'status': False, 'msg': 'Tor rejected the change, so it was rolled back: '
                                                       + (vc.get('output', '') or '').strip()[-300:]})
        self._exec('systemctl restart %s 2>&1' % self._detect_service_name(), timeout=30)
        return json.dumps({'status': True, 'backup': bak,
                           'msg': 'Control port enabled on 127.0.0.1:%d with cookie authentication. '
                                  'Tor was restarted, which briefly interrupts every hidden service.'
                                  % self.__ob_control_port})

    def onionbalance_status(self, args=None):
        cfg = self._ob_read_config()
        return json.dumps({
            'status': True,
            'installed': self._ob_installed(),
            'installing': self._file_exists(self.__ob_install_flag),
            'version': self._ob_version(),
            'running': self._exec('systemctl is-active --quiet onionbalance')[2] == 0,
            'enabled': self._exec('systemctl is-enabled --quiet onionbalance')[2] == 0,
            'configured': bool(cfg['key']),
            'frontend': self._ob_frontend_address(),
            'instances': cfg['instances'],
            'tor_control': self._tor_control_state(),
            'service_file': self._file_exists(self.__ob_service),
        })

    def install_onionbalance(self, args=None):
        """Install the daemon into its own venv, in the background.

        The installer script is written into /opt/onionbalance (root-owned, 0700)
        rather than /tmp: a predictable filename in a world-writable directory
        that is then executed as root is a local privilege escalation waiting for
        a second account on the box.
        """
        if self._ob_installed():
            return json.dumps({'status': True, 'installed': True,
                               'msg': 'OnionBalance %s is already installed.' % self._ob_version()})
        try:
            os.makedirs(self.__ob_dir, mode=0o700, exist_ok=True)
            os.chmod(self.__ob_dir, 0o700)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot create %s: %s' % (self.__ob_dir, str(e))})

        script = (
            '#!/bin/bash\n'
            'exec > "%(log)s" 2>&1\n'
            'set -x\n'
            'echo "=== Installing OnionBalance ==="\n'
            'apt-get install -y python3-venv python3-dev build-essential libssl-dev || true\n'
            'python3 -m venv "%(venv)s" || { echo "RESULT:FAIL:venv creation failed"; rm -f "%(flag)s"; exit 1; }\n'
            '"%(venv)s/bin/pip" install --upgrade pip setuptools wheel\n'
            '"%(venv)s/bin/pip" install onionbalance || { echo "RESULT:FAIL:pip install failed"; rm -f "%(flag)s"; exit 1; }\n'
            'if [ ! -x "%(bin)s" ]; then echo "RESULT:FAIL:binary missing after install"; rm -f "%(flag)s"; exit 1; fi\n'
            '"%(bin)s" --version || true\n'
            'echo "RESULT:OK"\n'
            'rm -f "%(flag)s"\n'
        ) % {'log': self.__ob_install_log, 'venv': self.__ob_venv,
             'bin': self.__ob_bin, 'flag': self.__ob_install_flag}

        script_path = os.path.join(self.__ob_dir, 'install.sh')
        ok, err = self._write_file(script_path, script)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot write installer: ' + err})
        try:
            os.chmod(script_path, 0o700)
            self._write_file(self.__ob_install_flag, 'running\n')
        except Exception as e:
            return json.dumps({'status': False, 'msg': str(e)})
        subprocess.Popen(['bash', script_path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         env=self._env(), start_new_session=True)
        return json.dumps({'status': True, 'background': True,
                           'msg': 'Installing OnionBalance in the background.'})

    def onionbalance_install_progress(self, args=None):
        ok, log, _ = self._read_file(self.__ob_install_log)
        log = log if ok else '(waiting for the installer to start...)'
        running = self._file_exists(self.__ob_install_flag)
        return json.dumps({'status': True, 'log': log[-8000:], 'running': running,
                           'done': 'RESULT:OK' in log, 'failed': 'RESULT:FAIL' in log,
                           'installed': self._ob_installed()})

    def _ob_write_config(self, instances):
        """Write the daemon config from validated values only.

        Hand-written rather than serialised: every value here is either a fixed
        path or an address already matched against the v3 base32 alphabet, so
        there is nothing a caller could smuggle into the file.
        """
        lines = ['# Generated by Tor Manager - do not edit by hand.',
                 '# Frontend key: %s' % self.__ob_key,
                 'services:',
                 '- key: %s' % self.__ob_key,
                 '  instances:']
        for addr in instances:
            lines.append('  - address: %s' % addr)
        return self._write_file(self.__ob_config, '\n'.join(lines) + '\n')

    def _ob_write_service(self):
        unit = (
            '[Unit]\n'
            'Description=OnionBalance - descriptor publisher for a balanced .onion\n'
            'After=network.target tor.service\n'
            'Requires=tor.service\n\n'
            '[Service]\n'
            'Type=simple\n'
            # Root because the daemon reads Tor's control auth cookie, which is
            # mode 0600 and owned by the Tor user.
            'User=root\n'
            'ExecStart=%s -c %s -v info\n'
            'Restart=on-failure\n'
            'RestartSec=10\n\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n'
        ) % (self.__ob_bin, self.__ob_config)
        ok, err = self._write_file(self.__ob_service, unit)
        if ok:
            self._exec('systemctl daemon-reload')
        return ok, err

    def set_onionbalance_frontend(self, args):
        """Promote an existing hidden service to be the balanced frontend.

        The address is preserved, which is the point: clients keep using the
        .onion they already have. The service is removed from torrc in the same
        step, because leaving it there would have this Tor and OnionBalance both
        publishing descriptors for the same address, fighting each other. Its
        directory and keys are kept, so the move can be undone from the Domains
        tab.
        """
        hs_dir, err = self._resolve_hs_dir(args.get('dir', ''))
        if not hs_dir:
            return json.dumps({'status': False, 'msg': err})
        ok, host, _ = self._read_file(os.path.join(hs_dir, 'hostname'))
        address = host.strip().lower() if ok else ''
        if not self._valid_onion(address):
            return json.dumps({'status': False,
                               'msg': 'That service has no published .onion hostname yet.'})
        sec_path = os.path.join(hs_dir, 'hs_ed25519_secret_key')
        if not self._file_exists(sec_path):
            return json.dumps({'status': False, 'msg': 'No hs_ed25519_secret_key in %s.' % hs_dir})

        try:
            os.makedirs(self.__ob_dir, mode=0o700, exist_ok=True)
            shutil.copy2(sec_path, self.__ob_key)
            os.chmod(self.__ob_key, 0o600)
            pub_path = os.path.join(hs_dir, 'hs_ed25519_public_key')
            if self._file_exists(pub_path):
                shutil.copy2(pub_path, self.__ob_key + '.pub')
                os.chmod(self.__ob_key + '.pub', 0o600)
            self._write_file(self.__ob_key + '.address', address + '\n')
            os.chmod(self.__ob_key + '.address', 0o600)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot install the frontend key: ' + str(e)})

        removed = json.loads(self.delete_domain({'dir': hs_dir, 'delete_files': 'false'}))
        if not removed.get('status'):
            return json.dumps({'status': False,
                               'msg': 'Frontend key copied, but removing the service from torrc failed: %s. '
                                      'Remove it from the Domains tab before starting OnionBalance, or the '
                                      'local Tor and OnionBalance will both publish descriptors for %s.'
                                      % (removed.get('msg', ''), address)})

        cfg = self._ob_read_config()
        wok, werr = self._ob_write_config(cfg['instances'])
        if not wok:
            return json.dumps({'status': False, 'msg': 'Cannot write the config: ' + werr})
        self._ob_write_service()
        return json.dumps({'status': True, 'frontend': address, 'dir': hs_dir,
                           'backup': removed.get('backup', ''),
                           'msg': '%s is now the OnionBalance frontend. It was removed from torrc so only '
                                  'OnionBalance publishes it; its keys are still in %s, so you can put it '
                                  'back from the Domains tab.' % (address, hs_dir)})

    def add_onionbalance_backend(self, args):
        """Register a backend instance. These usually live on other servers."""
        addr = (args.get('address', '') or '').strip().lower()
        if addr.endswith('/'):
            addr = addr[:-1]
        if not re.match(r'^[a-z2-7]{56}\.onion$', addr):
            return json.dumps({'status': False,
                               'msg': 'Enter a full v3 .onion address (56 characters plus ".onion").'})
        cfg = self._ob_read_config()
        if not cfg['key']:
            return json.dumps({'status': False, 'msg': 'Set the frontend service first.'})
        if addr == self._ob_frontend_address():
            return json.dumps({'status': False,
                               'msg': 'That is the frontend address. A backend must be a different '
                                      'hidden service, otherwise the descriptor points at itself.'})
        if addr in cfg['instances']:
            return json.dumps({'status': False, 'msg': 'That backend is already listed.'})
        instances = cfg['instances'] + [addr]
        ok, err = self._ob_write_config(instances)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot write the config: ' + err})
        return json.dumps({'status': True, 'instances': instances, 'reload_needed': True,
                           'msg': 'Backend added. Restart OnionBalance to publish the change.'})

    def remove_onionbalance_backend(self, args):
        addr = (args.get('address', '') or '').strip().lower()
        cfg = self._ob_read_config()
        if addr not in cfg['instances']:
            return json.dumps({'status': False, 'msg': 'That backend is not listed.'})
        instances = [a for a in cfg['instances'] if a != addr]
        ok, err = self._ob_write_config(instances)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot write the config: ' + err})
        return json.dumps({'status': True, 'instances': instances, 'reload_needed': True,
                           'msg': 'Backend removed. Restart OnionBalance to publish the change.'})

    def onionbalance_service(self, args):
        """Start, stop, restart, enable or disable the daemon."""
        action = (args.get('action', '') or '').strip().lower()
        if action not in ('start', 'stop', 'restart', 'enable', 'disable'):
            return json.dumps({'status': False, 'msg': 'Invalid action.'})
        if action in ('start', 'restart'):
            cfg = self._ob_read_config()
            if not cfg['key']:
                return json.dumps({'status': False, 'msg': 'Set the frontend service first.'})
            if not cfg['instances']:
                return json.dumps({'status': False,
                                   'msg': 'Add at least one backend first. With no instances there is '
                                          'nothing to publish and the frontend address goes dark.'})
            ctrl = self._tor_control_state()
            if not ctrl['listening']:
                return json.dumps({'status': False,
                                   'msg': 'Tor is not listening on its control port, which OnionBalance '
                                          'needs. Enable it first.'})
            if not self._file_exists(self.__ob_service):
                self._ob_write_service()
        _, e, c = self._exec('systemctl %s onionbalance 2>&1' % action, timeout=30)
        if c != 0:
            return json.dumps({'status': False, 'msg': 'systemctl %s failed: %s' % (action, e)})
        return json.dumps({'status': True, 'msg': 'OnionBalance %sed.' % action.rstrip('e')})

    def get_onionbalance_logs(self, args=None):
        lines = 100
        if args and args.get('lines'):
            try: lines = min(max(int(args['lines']), 10), 1000)
            except (TypeError, ValueError): pass
        o, _, c = self._exec('journalctl -u onionbalance --no-pager -n %d 2>/dev/null' % lines)
        if c == 0 and o and len(o) > 20:
            return json.dumps({'status': True, 'logs': o, 'source': 'journalctl'})
        ok, content, _ = self._read_file(self.__ob_log)
        if ok and content.strip():
            return json.dumps({'status': True, 'logs': '\n'.join(content.splitlines()[-lines:]),
                               'source': self.__ob_log})
        return json.dumps({'status': False, 'logs': 'No OnionBalance logs yet.', 'source': ''})
