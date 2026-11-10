# Sandbar Registrar

A pretend domain registrar for an isolated networking lab. Students sign up, search for a name under
`.beach`, and request it for their web-server VM. The instructor approves the request, and the registrar
writes the records into Bind9 on `dns-dominica` automatically. A real WHOIS server (port 43) answers
`whois -h registrar.sandbar.lab mysite.beach`.

**Student names exist only under `.beach`.** The registrar can never create `.lab` or `*.sandbar.lab` names,
and your existing `sandbar.lab` zone is never modified.

```
 student browser ──http:80──►  registrar (LXC, 10.0.50.50)  ──RFC 2136 + TSIG──►  dns-dominica (10.0.10.25)
 student terminal ─whois:43─►   Flask app + SQLite + WHOIS                         new zone: beach (dynamic)
                                                                                    sandbar.lab: untouched
```

**Rules:** once a name is approved, students can add subdomains such as `blog.mysite.beach` (A records or CNAME aliases within their own domain, `MAX_RECORDS_PER_DOMAIN`, default 5) · one name per student by default (`MAX_DOMAINS_PER_STUDENT`) · every request needs approval · `www.` comes free ·
names are 3-40 chars of `a-z 0-9 -` · lab infrastructure names are reserved · IPs must be in `10.0.0.0/8`
(`ALLOWED_NETWORKS`) and outside `DENIED_NETWORKS` (the DNS server is always blocked).

## Install

### 1. On `dns-dominica` (Bind9): once
Copy `deploy/bind9/` to the server, then:
```bash
sudo ./install-bind-config.sh
```
This creates a TSIG key, the `beach` zone file (in `/var/lib/bind`), and the zone config with a locked-down
`update-policy`, then validates everything with `named-checkconf -z` and reloads Bind9. It **rolls back
automatically** if validation fails, and never overwrites an existing key or zone.

What it changes on the server: it adds `registrar.key`, `named.conf.registrar` and `db.beach`, and appends one
`include` line to `named.conf.local` (the original is backed up as `named.conf.local.bak-<time>`).
It does **not** touch your `sandbar.lab` zone or its file. It prints a `TSIG_SECRET`: keep that for step 2.
Overrides, if needed: `NS_HOST`, `BIND_ETC`, `BIND_VAR`, `BIND_USER`.

Verify that the key can do only what it should (this tries to attack your zones; every DENY must be refused):
```bash
TSIG_SECRET=... DNS_SERVER=10.0.10.25 python3 tests/bind_policy_check.py
```

### 2. In the registrar container
Create an **unprivileged Debian 13 LXC** in Proxmox (512 MB RAM, 2 GB disk is plenty) with static IP
`10.0.50.50`, DNS `10.0.10.25`. Copy this repo into it, then:
```bash
sudo ./deploy/setup-lxc.sh
sudo nano /etc/registrar/registrar.env          # paste TSIG_SECRET; consider setting SIGNUP_CODE
cd /opt/registrar/app && sudo -u registrar env $(grep -v '^#' /etc/registrar/registrar.env | xargs) \
    PYTHONPATH=. python3 -m registrar.cli create-admin YOURNAME
sudo systemctl restart registrar-web registrar-whois
```
Add `registrar IN A 10.0.50.50` to your `sandbar.lab` zone so students can reach `http://registrar.sandbar.lab`.

### 3. Try it
Sign up as a student, request a name, log in as the instructor, approve, then:
```bash
dig +short mysite.beach @10.0.10.25
whois -h registrar.sandbar.lab mysite.beach
```
Students should type `http://mysite.beach` in full, since a bare `mysite.beach` may be treated as a search.

## Day-to-day
| Task | How |
|---|---|
| Approve / reject / revoke | Web UI → **Admin** (a red badge shows pending requests) |
| Check what DNS really says | Admin → All domains → **Check DNS** |
| Re-send everything to DNS (e.g. after restoring Bind9) | Admin → **Re-sync DNS**, or `python3 -m registrar.cli resync` |
| Reset a student's password | `python3 -m registrar.cli set-password USER` |
| List active domains | `python3 -m registrar.cli list` |
| Back up | copy `/var/lib/registrar/registrar.db` (the database is the source of truth; DNS is rebuilt from it) |
| Start a new class | stop services, delete the DB, empty the beach zone (`rndc freeze beach`, delete `/var/lib/bind/db.beach` and its `.jnl`, re-run the installer, `rndc thaw`/restart), start services |

## How safe is it for Bind9?
* The registrar's **TSIG key** can only add/replace/delete `A` and `CNAME` records under `beach.` (that covers student subdomains too, so no Bind9 change was needed for them). It cannot
  touch `NS`, `SOA` or the zone apex, and BIND refuses every update the key signs for any other zone,
  including `sandbar.lab`. `tests/bind_policy_check.py` proves each of these against a real Bind9.
* **`.lab` is impossible by design, in three layers:** the app refuses to start if `TLDS` contains `lab` or
  `*.lab`; search, registration and WHOIS reject those names; and the DNS layer refuses to address any zone that
  isn't a configured student zone. All three are covered by tests.
* The app **never shells out**: updates are built with `dnspython`, and every name and IP is validated first.
* The key lives only in `/etc/registrar/registrar.env` (mode 640, `root:registrar`). Students never see it.
  To rotate it, delete `/etc/bind/registrar.key`, re-run `install-bind-config.sh`, and update the env file.
* BIND can't restrict a TSIG key to a source IP when `update-policy` is used, so the key itself is the
  security boundary (HMAC-SHA256). Keep it only on the registrar container.
* BIND keeps a journal (`.jnl`) next to `/var/lib/bind/db.beach`. Don't hand-edit that file while Bind9
  runs (use `rndc freeze beach` / `rndc thaw beach`).

## Development / tests
```bash
python3 -m unittest discover -s tests -v          # 30 tests, DNS faked
# against a real Bind9 (e.g. a throwaway named on port 5300):
LIVE_DNS_SERVER=127.0.0.1 LIVE_DNS_PORT=5300 LIVE_TSIG_SECRET=... python3 -m unittest discover -s tests -v
```
To try the UI without any DNS server: `DNS_DRY_RUN=true`.

Layout: `app/registrar/` (Flask app, WHOIS server, CLI) · `deploy/` (LXC setup, systemd units, Bind9 config) · `tests/`.
