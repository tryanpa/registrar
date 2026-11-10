#!/usr/bin/env bash
# Run as root INSIDE the registrar container (Debian 13), from the unpacked repo:
#
#     sudo ./deploy/setup-lxc.sh
#
# Installs the dependencies from Debian's own packages (no pip, no internet at runtime),
# creates an unprivileged "registrar" user, installs the app and two systemd services.
# Safe to re-run to upgrade the code: it never overwrites /etc/registrar/registrar.env or the database.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Please run as root." >&2; exit 1; }
HERE=$(dirname "$(readlink -f "$0")")
SRC=$(dirname "$HERE")

# Only touch apt when something is actually missing, so routine updates ("git pull" + this script)
# keep working even if the Debian mirror is down or stale.
# If your mirror's Release files have expired, you can run:
#     APT_OPTS="-o Acquire::Check-Valid-Until=false" ./deploy/setup-lxc.sh
PKGS="python3 python3-flask python3-dnspython gunicorn whois dnsutils"
missing=""
for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
if [ -n "$missing" ]; then
    echo "==> Installing packages:$missing"
    apt-get ${APT_OPTS:-} update -qq
    apt-get ${APT_OPTS:-} install -y -qq $missing
else
    echo "==> Required packages already installed (skipping apt)"
fi

echo "==> Creating user and directories"
id registrar >/dev/null 2>&1 || useradd --system --home-dir /var/lib/registrar --shell /usr/sbin/nologin registrar
install -d -o registrar -g registrar -m 750 /var/lib/registrar
install -d -o root -g registrar -m 750 /etc/registrar

echo "==> Installing the application to /opt/registrar"
rm -rf /opt/registrar/app
install -d /opt/registrar
cp -r "$SRC/app" /opt/registrar/app
find /opt/registrar -name __pycache__ -type d -prune -exec rm -rf {} +
chown -R root:root /opt/registrar
chmod -R go-w /opt/registrar

ENVF=/etc/registrar/registrar.env
if [ ! -f "$ENVF" ]; then
    echo "==> Creating $ENVF"
    sed "s|^REGISTRAR_SECRET_KEY=.*|REGISTRAR_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))')|" \
        "$HERE/registrar.env.example" > "$ENVF"
    chown root:registrar "$ENVF"; chmod 640 "$ENVF"
    NEED_SECRET=1
else
    echo "==> Keeping existing $ENVF"
    NEED_SECRET=0
fi

echo "==> Installing systemd services"
cp "$HERE/registrar-web.service" "$HERE/registrar-whois.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable registrar-web.service registrar-whois.service >/dev/null

if grep -q '^TSIG_SECRET=paste-the-secret' "$ENVF"; then
    cat <<EOF

=== Almost done ===
1. On dns-dominica run deploy/bind9/install-bind-config.sh and copy the TSIG_SECRET it prints into
       $ENVF
2. Create your instructor login:
       cd /opt/registrar/app && sudo -u registrar env \$(grep -v '^#' $ENVF | xargs) PYTHONPATH=. python3 -m registrar.cli create-admin YOURNAME
3. Start everything:
       systemctl restart registrar-web registrar-whois
4. Add a DNS record for this server in your sandbar.lab zone:   registrar  IN A  10.0.50.50
EOF
else
    systemctl restart registrar-web.service registrar-whois.service
    echo "==> Services restarted."
fi
