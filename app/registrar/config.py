"""Configuration, read from environment variables (see deploy/registrar.env.example)."""
import ipaddress
import os
from dataclasses import dataclass


def _csv(value):
    return tuple(x.strip().lower() for x in value.split(",") if x.strip())


def _tlds(value):
    """Student names live ONLY under .beach. The lab's own zone (lab / sandbar.lab) must never be served
    by the registrar, so refuse to start if someone configures it."""
    tlds = _csv(value)
    for t in tlds:
        if t == "lab" or t.endswith(".lab"):
            raise RuntimeError(f"TLDS may not include '{t}': the registrar only manages student zones such as 'beach'")
    if not tlds:
        raise RuntimeError("TLDS is empty")
    return tlds


def _bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    secret_key: str
    db_path: str
    # DNS server that receives the RFC 2136 dynamic updates
    dns_server: str
    dns_port: int
    tsig_name: str
    tsig_secret: str
    tsig_algorithm: str
    dns_dry_run: bool          # log DNS changes instead of sending them (for demos/tests)
    ttl: int
    tlds: tuple
    ns_hostname: str           # shown in WHOIS as the name server
    registrar_host: str
    registrar_name: str
    allowed_nets: tuple        # student IPs must fall inside one of these networks
    denied_nets: tuple         # ...and must NOT fall inside any of these (lab infrastructure)
    signup_code: str           # optional class join code; empty = open sign-up
    cookie_secure: bool
    whois_bind: str
    whois_port: int
    whois_show_email: bool
    reserved_extra: tuple
    max_records: int           # subdomains (A/CNAME records) a student may add under each domain
    max_domains: int           # active (pending + approved) names one student may hold


def from_env(env=None):
    env = os.environ if env is None else env
    secret = env.get("REGISTRAR_SECRET_KEY", "")
    if not secret:
        raise RuntimeError("REGISTRAR_SECRET_KEY is not set (see /etc/registrar/registrar.env)")
    nets = tuple(
        ipaddress.ip_network(n, strict=False)
        for n in _csv(env.get("ALLOWED_NETWORKS", "10.0.0.0/8"))
    )
    denied_text = env.get("DENIED_NETWORKS", "")
    try:
        denied = [ipaddress.ip_network(n, strict=False) for n in _csv(denied_text)]
    except ValueError as exc:
        raise RuntimeError(f"DENIED_NETWORKS is not a comma-separated list of CIDR ranges: {exc}") from exc
    # the DNS server itself is always off limits, whatever else is configured
    denied.append(ipaddress.ip_network(env.get("DNS_SERVER", "10.0.10.25") + "/32", strict=False))
    return Config(
        secret_key=secret,
        db_path=env.get("REGISTRAR_DB", "/var/lib/registrar/registrar.db"),
        dns_server=env.get("DNS_SERVER", "10.0.10.25"),
        dns_port=int(env.get("DNS_PORT", "53")),
        tsig_name=env.get("TSIG_KEY_NAME", "registrar-key"),
        tsig_secret=env.get("TSIG_SECRET", ""),
        tsig_algorithm=env.get("TSIG_ALGORITHM", "hmac-sha256"),
        dns_dry_run=_bool(env.get("DNS_DRY_RUN", "false")),
        ttl=int(env.get("RECORD_TTL", "300")),
        tlds=_tlds(env.get("TLDS", "beach")),
        ns_hostname=env.get("NS_HOSTNAME", "dns-dominica.sandbar.lab"),
        registrar_host=env.get("REGISTRAR_HOST", "registrar.sandbar.lab"),
        registrar_name=env.get("REGISTRAR_NAME", "Sandbar Registrar"),
        allowed_nets=nets,
        denied_nets=tuple(denied),
        signup_code=env.get("SIGNUP_CODE", ""),
        cookie_secure=_bool(env.get("COOKIE_SECURE", "false")),
        whois_bind=env.get("WHOIS_BIND", "0.0.0.0"),
        whois_port=int(env.get("WHOIS_PORT", "43")),
        whois_show_email=_bool(env.get("WHOIS_SHOW_EMAIL", "false")),
        reserved_extra=_csv(env.get("RESERVED_NAMES", "")),
        max_records=max(0, int(env.get("MAX_RECORDS_PER_DOMAIN", "5"))),
        max_domains=max(1, int(env.get("MAX_DOMAINS_PER_STUDENT", "1"))),
    )
