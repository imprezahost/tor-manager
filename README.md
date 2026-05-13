# Tor Manager

> Install Tor, manage hidden services and edit `torrc` from your **aaPanel** dashboard.

Tor Manager is an aaPanel plugin that deploys the Tor daemon, creates and manages `.onion` hidden services, and exposes the full `torrc` directive catalogue in a friendly UI — no SSH required.

---

## Better together: pair with Onion Guard

Tor Manager handles **provisioning**: getting Tor installed and `.onion` services configured. To **protect those services at runtime** from bots, scrapers and DDoS, install our companion plugin:

> **[Onion Guard](https://github.com/imprezahost/onion-guard)** — Proof-of-Work challenge + firewall + reverse proxy for `.onion` services.

```
  Tor Manager   ----->  creates and configures hidden services in /etc/tor/torrc
                            |
                            v
  Onion Guard   ----->  auto-discovers them, applies PoW + firewall + proxy
                            |
                            v
                          your application (WordPress, etc.)
```

Either plugin works on its own. Installing both gives you a complete pipeline: provisioning + protection, all from the aaPanel UI.

---

## Highlights

### Tor service management

- Detects an installed Tor binary across `/usr/bin`, `/usr/local/bin`, `/snap/bin`, etc. with multiple fallback probes
- One-click install on Debian / Ubuntu / RHEL families - detects distro and codename automatically
- Start / stop / restart / reload / enable / disable from the panel
- Version detection and update check
- Repository fix-up for distros that ship a broken Tor entry

### Hidden services (.onion)

- Create, list and remove hidden services
- Each service maps a virtual port (typically 80) to a local backend (`127.0.0.1:port`)
- Auto-displays the generated `.onion` hostname once Tor publishes the descriptor
- Safe remove workflow that cleans up the `torrc` block, comments and `HiddenServiceDir`
- One-click "Add to aaPanel" — registers the hidden service as a site for the configured backend
- Backup: download the hidden service keys (`hostname`, `hs_ed25519_secret_key`, `hs_ed25519_public_key`) as a zip

### Vanity `.onion` addresses

- Built-in support for [`mkp224o`](https://github.com/cathugger/mkp224o) (Ed25519 vanity generator for v3 onions)
- One-click compile and install from source - no system package needed
- Background generation with status, rate and ETA in the panel
- Apply found keys directly to a new hidden service

### Full `torrc` editor

- Categorised directive list with descriptions (network, general, hidden service, advanced, performance, relay)
- Inline-edit any directive without dropping to a shell
- Multi-value directives (like `HiddenServicePort`) handled correctly
- `tor --verify-config` validation before saving

### File editor

- Direct read / write access to `torrc` and `torrc-defaults`
- Read-only access to `tor.log`, `notices.log` and hidden-service keys (so secrets can be inspected but never accidentally overwritten)

### Live logs

- Tail `tor.log`, `notices.log` and journalctl output of the Tor service from the panel

---

## Installation

### Requirements

- aaPanel 7.x or newer on Linux
- Root access (the plugin installs the Tor package and writes to `/etc/tor/`)
- Outbound network access to your distro's repositories
- Optional: outbound access to GitHub (only if you want to install `mkp224o` for vanity addresses)

### Install

```bash
# On your aaPanel server, as root:
cd /www/server/panel/plugin
git clone https://github.com/imprezahost/tor-manager.git tor_manager
bash tor_manager/install.sh
bt restart
```

Then open the aaPanel UI and go to **App Store / Installed**. The **Tor Manager** icon will appear (hard-refresh with `Ctrl+Shift+R` if not visible).

The first time you open the plugin, a diagnostic checks your distro, Tor binary, service file, `torrc` and permissions. If Tor isn't installed, you can deploy it with one click.

### Uninstall

```bash
bash /www/server/panel/plugin/tor_manager/uninstall.sh
```

Removing the plugin **does not** uninstall Tor itself, delete your `torrc`, or remove your hidden services. To remove Tor entirely, use **Status --> Uninstall Tor** in the panel before removing the plugin.

---

## Panel tabs

| Tab | What it does |
|---|---|
| **Status** | Tor version, service state, hidden-service summary, distro info |
| **Domains** | Create, list and remove hidden services; generate vanity `.onion` addresses |
| **Control** | Start / stop / restart / reload Tor; enable / disable on boot; verify config |
| **Config** | Inline editor for every `torrc` directive, organised by category |
| **Editor** | Direct file access to `torrc`, logs and hidden-service keys (read-only where appropriate) |
| **Logs** | Live log tail |

---

## On-disk layout

| Path | Purpose |
|---|---|
| `/etc/tor/torrc` | Main Tor configuration |
| `/etc/tor/torrc-defaults` | Distro-shipped defaults |
| `/var/lib/tor/<service>/hostname` | The `.onion` address for a hidden service |
| `/var/lib/tor/<service>/hs_ed25519_*_key` | Ed25519 keys (back these up!) |
| `/var/log/tor/log`, `/var/log/tor/notices.log` | Tor logs |
| `/usr/local/bin/mkp224o` | Vanity generator (optional, installed on demand) |

---

## Security notes

- The plugin runs as the aaPanel user (typically root). It executes `tor`, `systemctl` and edits `/etc/tor/torrc`.
- Hidden-service private keys (`hs_ed25519_secret_key`) are shown as read-only in the Editor tab to prevent accidental overwrite. **Treat them as you would an SSH private key.**
- The "Download keys" action bundles all three key files of a hidden service into a zip - useful for backup, but the zip is not encrypted; transfer over a secure channel and store accordingly.
- `tor --verify-config` is run before saving any `torrc` change to catch syntax errors early.

---

## Author

Built and maintained by [Impreza Host](https://imprezahost.com). Issues and pull requests welcome.
