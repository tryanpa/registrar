"""Builds WHOIS responses. Shared by the port-43 server and the web 'WHOIS' page."""
import datetime
import re

from . import validation as v


def _iso(ts):
    """'2026-11-10 14:03:11' -> '2026-11-10T14:03:11Z'"""
    return ts.replace(" ", "T") + "Z" if ts else ""


def _oneline(text, limit=120):
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def _footer():
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f">>> Last update of WHOIS database: {now} <<<\n"


def whois_text(cfg, conn, query):
    raw = v.clean_query(query)
    if not raw:
        return "% Usage: whois -h %s <domain>\n" % cfg.registrar_host
    try:
        label, tld = v.split_domain(raw, cfg.tlds)
    except ValueError as exc:
        return f"% {exc}\n"
    if tld is None:
        return ("% Please query a full domain name, for example: %s.%s\n"
                % (label or "mysite", cfg.tlds[0]))
    fqdn = f"{label}.{tld}".upper()

    if v.is_reserved(label, cfg.reserved_extra):
        return (f"Domain Name: {fqdn}\nDomain Status: serverHold (reserved by the registry)\n"
                f"Registrar: {cfg.registrar_name}\n\n{_footer()}")

    row = conn.execute(
        """SELECT d.*, u.display_name FROM domains d JOIN users u ON u.id = d.owner_id
           WHERE d.name=? AND d.tld=? AND d.status IN ('pending','approved')""",
        (label, tld),
    ).fetchone()
    if row is None:
        return f'No match for "{fqdn}".\n\n{_footer()}'

    lines = [
        f"Domain Name: {fqdn}",
        f"Registry Domain ID: {row['id']}-{tld.upper()}",
        f"Registrar WHOIS Server: {cfg.registrar_host}",
        f"Registrar URL: http://{cfg.registrar_host}/",
        f"Updated Date: {_iso(row['updated_at'])}",
        f"Creation Date: {_iso(row['created_at'])}",
        f"Registrar: {cfg.registrar_name}",
        "Domain Status: " + ("ok" if row["status"] == "approved" else "pendingCreate"),
        f"Registrant Name: {_oneline(row['display_name'], 80)}",
    ]
    if row["purpose"]:
        lines.append(f"Registrant Comment: {_oneline(row['purpose'])}")
    if cfg.whois_show_email:
        email = conn.execute("SELECT email FROM users WHERE id=?", (row["owner_id"],)).fetchone()["email"]
        lines.append(f"Registrant Email: {email or 'n/a'}")
    else:
        lines.append("Registrant Email: REDACTED FOR PRIVACY")
    if row["status"] == "approved":
        lines.append(f"Name Server: {cfg.ns_hostname.upper()}")
    lines.append("DNSSEC: unsigned")
    return "\n".join(lines) + "\n\n" + _footer()
