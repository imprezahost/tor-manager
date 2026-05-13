# coding: utf-8
# Tor Service Manager - aaPanel Plugin v2.6

import sys
import os
import json
import re
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

    def _exec(self, cmd, timeout=30):
        try:
            env = os.environ.copy()
            env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'
            env['HOME'] = '/root'
            r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout, env=env)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timed out', 1
        except Exception as e:
            return '', str(e), 1

    def _file_exists(self, path):
        _, _, c = self._exec('test -f "%s"' % path)
        return c == 0

    def _dir_exists(self, path):
        _, _, c = self._exec('test -d "%s"' % path)
        return c == 0

    def _file_size(self, path):
        s, _, c = self._exec('stat -c "%%s" "%s" 2>/dev/null' % path)
        try: return int(s) if c == 0 else 0
        except: return 0

    def _read_file_shell(self, path):
        s, e, c = self._exec('cat "%s" 2>/dev/null' % path)
        if c == 0: return True, s, False
        ft, _, _ = self._exec('file -b "%s" 2>/dev/null' % path)
        if any(w in ft.lower() for w in ['binary', 'key', 'data']):
            return True, '[Binary file]', True
        return False, 'Cannot read: ' + e, False

    def _write_file_shell(self, path, content):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, ''
        except Exception as e:
            return False, str(e)

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
        ok, content, _ = self._read_file_shell('/etc/tor/torrc')
        if ok:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('User ') and not line.startswith('#'):
                    return line.split()[1]
        s, _, c = self._exec("ps -eo user:32,comm 2>/dev/null | grep -E '\\btor$' | awk '{print $1}' | head -1")
        if c == 0 and s: return s
        for u in ['debian-tor', 'tor', '_tor']:
            _, _, c = self._exec('id %s 2>/dev/null' % u)
            if c == 0: return u
        return 'root'

    def _parse_torrc(self):
        ok, content, _ = self._read_file_shell('/etc/tor/torrc')
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
                s, _, c = self._exec('"%s" --version 2>/dev/null' % p)
                if c == 0 and 'Tor version' in s: return p, 'direct_path', results
                _, _, xc = self._exec('test -x "%s"' % p)
                if xc == 0: return p, 'direct_path(no_ver)', results
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
                    v, _, vc = self._exec('"%s" --version 2>/dev/null' % line.strip())
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
            ok, content, _ = self._read_file_shell(hs_dir + '/hostname')
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
        self._exec("echo '%s' > /etc/apt/sources.list.d/tor.list" % tl)

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
        cmd = ('sudo -u %s tor --verify-config 2>&1' % tu) if tu and tu != 'root' else 'tor --verify-config 2>&1'
        so, se, _ = self._exec(cmd, timeout=15)
        out = so if so else se
        return json.dumps({'status': 'Configuration was valid' in out, 'output': out, 'ran_as': tu})

    def get_file_list(self, args=None):
        result = []
        for f in self._get_important_files():
            exists = self._file_exists(f['path'])
            result.append({'key': f['key'], 'path': f['path'], 'label': f['label'], 'editable': f['editable'], 'exists': exists, 'size': self._file_size(f['path']) if exists else 0})
        return json.dumps(result)

    def read_file(self, args):
        fp = args.get('path', '').strip()
        if not fp: return json.dumps({'status': False, 'msg': 'No path.'})
        allowed = ['/etc/tor/', '/var/lib/tor/', '/var/log/tor/']
        if not any(fp.startswith(d) for d in allowed): return json.dumps({'status': False, 'msg': 'Access denied.'})
        if not self._file_exists(fp): return json.dumps({'status': False, 'msg': 'Not found: ' + fp})
        ok, content, ib = self._read_file_shell(fp)
        if ok: return json.dumps({'status': True, 'content': content, 'path': fp, 'is_binary': ib})
        return json.dumps({'status': False, 'msg': content})

    def save_file(self, args):
        fp = args.get('path', '').strip()
        content = args.get('content', '')
        if not fp: return json.dumps({'status': False, 'msg': 'No path.'})
        if not fp.startswith('/etc/tor/'): return json.dumps({'status': False, 'msg': 'Only /etc/tor/ editable.'})
        if not self._file_exists(fp): return json.dumps({'status': False, 'msg': 'Not found: ' + fp})
        bak = fp + '.bak.' + str(int(time.time()))
        self._exec('cp -p "%s" "%s"' % (fp, bak))
        ok, err = self._write_file_shell(fp, content)
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
        ok, content, _ = self._read_file_shell(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak = torrc_path + '.bak.' + str(int(time.time()))
        self._exec('cp -p "%s" "%s"' % (torrc_path, bak))

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
        ok, err = self._write_file_shell(torrc_path, new_content)
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
        ok, content, _ = self._read_file_shell(hs_dir + '/hostname')
        if ok and content.strip():
            info['hostname'] = content.strip()
            info['has_hostname'] = True
            # Check if this hostname exists in aaPanel's website list
            info['in_panel'] = self._site_exists_in_panel(info['hostname'])
        # Check for keys
        info['has_keys'] = self._file_exists(hs_dir + '/hs_ed25519_secret_key')
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
        hostname = args.get('hostname', '').strip()
        if not hostname or not hostname.endswith('.onion'):
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
                self._exec('mkdir -p "%s"' % site_path_final)
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
        if not ports:
            return json.dumps({'status': False, 'msg': 'At least one port mapping is required (e.g. "80 127.0.0.1:80").'})

        # Determine base directory
        data_dir = '/var/lib/tor'
        directives = self._parse_torrc()
        for key, val in directives:
            if key == 'DataDirectory':
                data_dir = val.rstrip('/')
                break

        hs_dir = data_dir + '/' + name

        # Check if already exists in torrc
        for key, val in directives:
            if key == 'HiddenServiceDir' and val.rstrip('/') == hs_dir:
                return json.dumps({'status': False, 'msg': 'Domain "%s" already exists in torrc.' % name})

        # Create directory with correct ownership
        tor_user = self._get_tor_user()
        self._exec('mkdir -p "%s"' % hs_dir)
        self._exec('chown %s:%s "%s"' % (tor_user, tor_user, hs_dir))
        self._exec('chmod 700 "%s"' % hs_dir)

        # Build torrc block
        block_lines = []
        block_lines.append('')
        block_lines.append('# Hidden Service: %s' % name)
        block_lines.append('HiddenServiceDir %s' % hs_dir)
        # Parse port lines
        for port_line in ports.split('\n'):
            port_line = port_line.strip()
            if port_line:
                block_lines.append('HiddenServicePort %s' % port_line)

        # Append to torrc
        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file_shell(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak = torrc_path + '.bak.' + str(int(time.time()))
        self._exec('cp -p "%s" "%s"' % (torrc_path, bak))

        new_content = content.rstrip('\n') + '\n' + '\n'.join(block_lines) + '\n'
        ok, err = self._write_file_shell(torrc_path, new_content)
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
            rok, hcontent, _ = self._read_file_shell(hs_dir + '/hostname')
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
        hs_dir = args.get('dir', '').strip().rstrip('/')
        delete_files = args.get('delete_files', 'false')

        if not hs_dir:
            return json.dumps({'status': False, 'msg': 'No domain directory specified.'})
        if not hs_dir.startswith('/var/lib/tor/'):
            return json.dumps({'status': False, 'msg': 'Invalid directory path.'})

        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file_shell(torrc_path)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})

        # Backup
        bak = torrc_path + '.bak.' + str(int(time.time()))
        self._exec('cp -p "%s" "%s"' % (torrc_path, bak))

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
                if dir_val == hs_dir:
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
        ok, err = self._write_file_shell(torrc_path, new_content)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Failed to write torrc: ' + err})

        # Delete files if requested
        if delete_files == 'true' and self._dir_exists(hs_dir):
            self._exec('rm -rf "%s"' % hs_dir)

        # Restart Tor
        svc = self._detect_service_name()
        _, se, c = self._exec('systemctl restart %s 2>&1' % svc, timeout=30)

        name = hs_dir.split('/')[-1]
        return json.dumps({
            'status': True,
            'msg': 'Domain "%s" removed. Backup: %s' % (name, bak),
            'backup': bak
        })

    def download_domain_keys(self, args):
        """Package domain keys into a downloadable tar.gz (base64 encoded)."""
        import base64
        hs_dir = args.get('dir', '').strip().rstrip('/')
        if not hs_dir:
            return json.dumps({'status': False, 'msg': 'No directory specified.'})
        if not hs_dir.startswith('/var/lib/tor/'):
            return json.dumps({'status': False, 'msg': 'Invalid directory.'})
        if not self._dir_exists(hs_dir):
            return json.dumps({'status': False, 'msg': 'Directory does not exist.'})

        name = hs_dir.split('/')[-1]
        tmp_tar = '/tmp/tor_keys_%s_%d.tar.gz' % (name, int(time.time()))

        # Create tar.gz of the domain directory
        _, se, c = self._exec('tar -czf "%s" -C "%s" . 2>&1' % (tmp_tar, hs_dir))
        if c != 0:
            return json.dumps({'status': False, 'msg': 'Failed to create archive: ' + se})

        # Read and base64 encode
        try:
            with open(tmp_tar, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('utf-8')
            os.remove(tmp_tar)
            return json.dumps({
                'status': True,
                'filename': '%s_keys.tar.gz' % name,
                'data': b64,
                'msg': 'Keys packaged for download.'
            })
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Failed: ' + str(e)})

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
        status_file = '/tmp/.tor_update_status'
        log_file = '/tmp/.tor_update_log'
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
        script_file = '/tmp/.tor_update.sh'
        self._exec('echo \'%s\' > %s && chmod +x %s' % (script.replace("'", "'\\''"), script_file, script_file))
        self._exec('echo "running" > %s' % status_file)
        self._exec('nohup bash %s > /dev/null 2>&1 &' % script_file)
        return json.dumps({'status': True, 'msg': 'Update started in background.', 'background': True})

    def update_tor_status(self, args=None):
        status_file = '/tmp/.tor_update_status'
        log_file = '/tmp/.tor_update_log'
        s, _, c = self._exec('cat %s 2>/dev/null' % status_file)
        if c != 0 or not s.strip():
            return json.dumps({'status': True, 'running': False, 'done': False})
        log, _, _ = self._exec('cat %s 2>/dev/null' % log_file)
        if 'RESULT:OK' in log:
            self._exec('rm -f %s %s /tmp/.tor_update.sh' % (status_file, log_file))
            return json.dumps({'status': True, 'running': False, 'done': True, 'success': True, 'msg': 'Tor updated to ' + self._get_tor_version(), 'version': self._get_tor_version(), 'log': log})
        if 'RESULT:FAIL' in log:
            self._exec('rm -f %s /tmp/.tor_update.sh' % status_file)
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
        self._exec('rm -rf /tmp/tor_vanity_* 2>/dev/null')
        return json.dumps({'status': True, 'msg': 'mkp224o removed.'})

    def benchmark_mkp224o(self, args=None):
        mkp_path = '/opt/mkp224o/mkp224o'
        if not self._file_exists(mkp_path):
            return json.dumps({'status': False, 'msg': 'mkp224o not installed.'})
        # Run ~5 sec benchmark with long prefix that won't match
        out_dir = '/tmp/mkp224o_bench_%d' % int(time.time())
        self._exec('mkdir -p "%s"' % out_dir)
        s, se, _ = self._exec('timeout 6 "%s" -B -S 3 -n 0 -d "%s" zzzzzzzzzz 2>&1; exit 0' % (mkp_path, out_dir), timeout=12)
        self._exec('rm -rf "%s"' % out_dir)
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
        self._exec('pkill -f "mkp224o.*-d /tmp/tor_vanity" 2>/dev/null')
        time.sleep(0.5)
        job_id = str(int(time.time()))
        out_dir = '/tmp/tor_vanity_%s' % job_id
        log_file = '/tmp/tor_vanity_%s.log' % job_id
        pid_file = '/tmp/tor_vanity_%s.pid' % job_id
        self._exec('rm -rf /tmp/tor_vanity_* 2>/dev/null')
        self._exec('mkdir -p "%s"' % out_dir)
        cores, _, _ = self._exec('nproc')
        try: threads = max(1, int(cores.strip()) - 1)
        except: threads = 1
        cmd = 'nohup "%s" -B -n 1 -t %d -d "%s" -S 5 %s > "%s" 2>&1 & echo $!' % (mkp_path, threads, out_dir, prefix, log_file)
        pid_out, _, _ = self._exec(cmd)
        if pid_out:
            self._exec('echo "%s" > "%s"' % (pid_out.strip(), pid_file))
        return json.dumps({'status': True, 'job_id': job_id, 'prefix': prefix, 'threads': threads})

    def check_vanity_status(self, args):
        job_id = args.get('job_id', '').strip()
        if not job_id: return json.dumps({'status': False, 'msg': 'No job ID.'})
        out_dir = '/tmp/tor_vanity_%s' % job_id
        log_file = '/tmp/tor_vanity_%s.log' % job_id
        pid_file = '/tmp/tor_vanity_%s.pid' % job_id
        pid = ''
        if self._file_exists(pid_file):
            p, _, _ = self._exec('cat "%s"' % pid_file)
            pid = p.strip()
        running = False
        if pid:
            _, _, c = self._exec('kill -0 %s 2>/dev/null' % pid)
            running = (c == 0)
        # Check for found .onion directory
        found_dir, found_hostname = '', ''
        ls_out, _, _ = self._exec('ls -d "%s"/*.onion 2>/dev/null | head -1' % out_dir)
        if ls_out and ls_out.strip():
            found_dir = ls_out.strip()
            h, _, _ = self._exec('cat "%s/hostname" 2>/dev/null' % found_dir)
            if h: found_hostname = h.strip()
        # Parse latest stats
        rate = ''
        if self._file_exists(log_file):
            s, _, _ = self._exec('tail -5 "%s" 2>/dev/null' % log_file)
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
        self._exec('pkill -f "mkp224o.*-d /tmp/tor_vanity" 2>/dev/null')
        self._exec('rm -rf /tmp/tor_vanity_* 2>/dev/null')
        return json.dumps({'status': True, 'msg': 'Cancelled.'})

    def apply_vanity_keys(self, args):
        keys_dir = args.get('keys_dir', '').strip()
        name = args.get('svc_name', args.get('name', '')).strip()
        ports = args.get('ports', '').strip()
        if not keys_dir or not name or not ports:
            return json.dumps({'status': False, 'msg': 'Missing parameters.'})
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            return json.dumps({'status': False, 'msg': 'Invalid name.'})
        if not self._dir_exists(keys_dir):
            return json.dumps({'status': False, 'msg': 'Keys directory not found.'})
        data_dir = '/var/lib/tor'
        hs_dir = data_dir + '/' + name
        for key, val in self._parse_torrc():
            if key == 'HiddenServiceDir' and val.rstrip('/') == hs_dir:
                return json.dumps({'status': False, 'msg': 'Domain "%s" already exists.' % name})
        tor_user = self._get_tor_user()
        self._exec('mkdir -p "%s"' % hs_dir)
        self._exec('cp -a "%s"/* "%s"/' % (keys_dir, hs_dir))
        self._exec('chown -R %s:%s "%s"' % (tor_user, tor_user, hs_dir))
        self._exec('chmod 700 "%s"' % hs_dir)
        self._exec('chmod 600 "%s"/*' % hs_dir)
        torrc_path = '/etc/tor/torrc'
        ok, content, _ = self._read_file_shell(torrc_path)
        if not ok: return json.dumps({'status': False, 'msg': 'Cannot read torrc.'})
        bak = torrc_path + '.bak.' + str(int(time.time()))
        self._exec('cp -p "%s" "%s"' % (torrc_path, bak))
        block = '\n\n# Hidden Service: %s (custom vanity)\nHiddenServiceDir %s' % (name, hs_dir)
        for pl in ports.split('\n'):
            pl = pl.strip()
            if pl: block += '\nHiddenServicePort %s' % pl
        ok, err = self._write_file_shell(torrc_path, content.rstrip('\n') + block + '\n')
        if not ok: return json.dumps({'status': False, 'msg': 'Failed: ' + err})
        svc = self._detect_service_name()
        self._exec('systemctl restart %s 2>&1' % svc, timeout=30)
        hostname = ''
        rok, hc, _ = self._read_file_shell(hs_dir + '/hostname')
        if rok and hc.strip(): hostname = hc.strip()
        self._exec('rm -rf /tmp/tor_vanity_* 2>/dev/null')
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
