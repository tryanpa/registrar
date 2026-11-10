"""Input validation. Everything that ends up in DNS passes through here first."""
import ipaddress
import re

# Names students may not register (lab infrastructure and confusing names).
RESERVED = frozenset("""
www ns ns1 ns2 dns dns-dominica registrar whois admin administrator root mail smtp imap pop
ftp ssh localhost sandbar beach lab gateway router switch firewall proxmox pve iperf iperf3
test example wpad autoconfig autodiscover hostmaster postmaster webmaster registry nic
""".split())

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$")  # no leading/trailing/double hyphen
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
MIN_LABEL, MAX_LABEL = 3, 40


def label_error(label, reserved_extra=()):
    """Return a human-readable problem with `label`, or None if it is acceptable."""
    if not (MIN_LABEL <= len(label) <= MAX_LABEL):
        return f"Names must be {MIN_LABEL}-{MAX_LABEL} characters long."
    if not LABEL_RE.match(label):
        return "Use only letters, numbers and single hyphens (no hyphen at the start or end)."
    if label in RESERVED or label in reserved_extra:
        return "That name is reserved by the lab."
    return None


def is_reserved(label, reserved_extra=()):
    return label in RESERVED or label in reserved_extra


def clean_query(text):
    """Normalise whatever a student typed in a search box."""
    t = (text or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)      # strip http://
    t = t.split("/")[0].rstrip(".")
    if t.startswith("www."):
        t = t[4:]
    return t


def split_domain(text, tlds):
    """'mysite.beach' -> ('mysite', 'beach'); 'mysite' -> ('mysite', None).
    Raises ValueError for a TLD we do not serve."""
    t = clean_query(text)
    if "." not in t:
        return t, None
    label, _, tld = t.rpartition(".")
    if tld not in tlds:                       # check the TLD first so .lab / sandbar.lab get the clearest message
        raise ValueError("We only register " + ", ".join("." + x for x in tlds) + " names.")
    if "." in label:
        raise ValueError("Please search for a single name such as 'mysite' (no subdomains).")
    return label, tld


def ip_error(text, allowed_nets, denied_nets=()):
    """Return (ip_string, None) if valid, else (None, message)."""
    try:
        ip = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None, "That doesn't look like an IPv4 address (example: 10.0.20.15)."
    if ip.version != 4:
        return None, "Only IPv4 addresses are supported."
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip == ipaddress.ip_address("255.255.255.255"):
        return None, "That address can't be used for a web server."
    if not any(ip in net for net in allowed_nets):
        nets = ", ".join(str(n) for n in allowed_nets)
        return None, f"The address must be inside the lab network ({nets})."
    if any(ip in net for net in denied_nets):
        return None, "That address belongs to lab infrastructure and can't be used for a student site."
    return str(ip), None


def username_error(name):
    if not USERNAME_RE.match(name):
        return "Usernames are 3-32 characters: lowercase letters, numbers, '.', '_' or '-'."
    return None
