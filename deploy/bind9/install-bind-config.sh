#!/usr/bin/env bash
# Run as root ON THE DNS SERVER (dns-dominica). Adds the "beach" zone and the
# registrar's restricted TSIG key to an existing Bind9, without touching sandbar.lab.
#
#   sudo ./install-bind-config.sh
#
# Safe to re-run: it never overwrites an existing key or zone file, backs up the files it edits,
# validates with named-checkconf before reloading, and rolls back if validation fails.
set -euo pipefail

BIND_ETC=${BIND_ETC:-/etc/bind}
BIND_VAR=${BIND_VAR:-/var/lib/bind}
BIND_USER=${BIND_USER:-bind}
NS_HOST=${NS_HOST:-dns-dominica.sandbar.lab}   # name server named in the beach zone (lives outside it, so no glue)
RELOAD=${RELOAD:-1}
HERE=$(dirname "$(readlink -f "$0")")
STAMP=$(date +%Y%m%d-%H%M%S)

[ "$(id -u)" -eq 0 ] || [ "${ALLOW_NONROOT:-0}" = 1 ] || { echo "Please run as root." >&2; exit 1; }
command -v tsig-keygen >/dev/null || { echo "tsig-keygen not found: is bind9-utils installed?" >&2; exit 1; }
[ -d "$BIND_ETC" ] || { echo "$BIND_ETC does not exist: is this the DNS server?" >&2; exit 1; }
mkdir -p "$BIND_VAR"

backups=()
created=""
# remember existing files so they can be restored; remember new files so they can be removed
backup() { if [ -e "$1" ]; then cp -p "$1" "$1.bak-$STAMP"; backups+=("$1"); else created="$created $1"; fi; }
rollback() {
    echo "Validation failed: restoring previous configuration." >&2
    for f in ${backups[@]+"${backups[@]}"}; do mv -f "$f.bak-$STAMP" "$f"; done
    for f in $created; do rm -f "$f"; done
    exit 1
}

# 1. TSIG key (only created once)
KEY="$BIND_ETC/registrar.key"
if [ ! -f "$KEY" ]; then
    tsig-keygen -a hmac-sha256 registrar-key > "$KEY"
    chown "root:$BIND_USER" "$KEY" 2>/dev/null || true
    chmod 640 "$KEY"
    created="$created $KEY"
    echo "Created TSIG key $KEY"
else
    echo "Keeping existing TSIG key $KEY"
fi

# 2. Zone files (only created if missing; BIND owns them afterwards)
zf="$BIND_VAR/db.beach"
if [ ! -f "$zf" ]; then
    sed "s/@@NS_HOST@@/$NS_HOST/g" "$HERE/db.beach.template" > "$zf"
    chown "$BIND_USER:$BIND_USER" "$zf" 2>/dev/null || true
    chmod 640 "$zf"
    created="$created $zf"
    echo "Created zone file $zf"
else
    echo "Keeping existing zone file $zf"
fi
# BIND must be able to create the .jnl journal next to the zone file
chown "$BIND_USER:$BIND_USER" "$BIND_VAR" 2>/dev/null || true

# 3. Zone configuration
CONF="$BIND_ETC/named.conf.registrar"
backup "$CONF"
sed -e "s#/etc/bind#$BIND_ETC#g" -e "s#/var/lib/bind#$BIND_VAR#g" "$HERE/named.conf.registrar" > "$CONF"

LOCAL="$BIND_ETC/named.conf.local"
INCLUDE="include \"$CONF\";"
backup "$LOCAL"
touch "$LOCAL"
grep -qF "$INCLUDE" "$LOCAL" || printf '\n// Student domain registrar zones\n%s\n' "$INCLUDE" >> "$LOCAL"

# 4. Validate (including loading the zone files) BEFORE reloading
MAIN="$BIND_ETC/named.conf"
[ -f "$MAIN" ] || MAIN="$LOCAL"
if ! named-checkconf -z "$MAIN"; then rollback; fi
echo "named-checkconf: OK"

# 5. Reload
if [ "$RELOAD" = 1 ]; then
    rndc reconfig && echo "Bind9 reconfigured."
fi

SECRET=$(awk -F'"' '/secret/ {print $2}' "$KEY")
cat <<EOF

=== Done ===
Put these in /etc/registrar/registrar.env on the registrar container:

    TSIG_KEY_NAME=registrar-key
    TSIG_ALGORITHM=hmac-sha256
    TSIG_SECRET=$SECRET

Treat the secret like a password: anyone holding it can create student names.
EOF
