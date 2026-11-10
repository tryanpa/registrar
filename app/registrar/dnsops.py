"""Talks to Bind9 using RFC 2136 dynamic updates, signed with a TSIG key.

Uses the dnspython library directly (no shelling out to nsupdate), and only ever
touches two record sets per domain:
    <name>.<tld>.      A      <student ip>
    www.<name>.<tld>.  CNAME  <name>.<tld>.
"""
import logging

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsigkeyring
import dns.update

log = logging.getLogger("registrar.dns")


class DnsError(Exception):
    pass


class Dns:
    def __init__(self, cfg):
        self.cfg = cfg
        self._keyring = None

    def _new_update(self, tld):
        if tld not in self.cfg.tlds:      # defence in depth: never address a zone we are not configured for
            raise DnsError(f"Refusing to update zone '{tld}': not a student zone")
        if self._keyring is None:
            if not self.cfg.tsig_secret:
                raise DnsError("TSIG_SECRET is not configured")
            self._keyring = dns.tsigkeyring.from_text({self.cfg.tsig_name: self.cfg.tsig_secret})
        return dns.update.Update(
            tld + ".",
            keyring=self._keyring,
            keyname=self.cfg.tsig_name,
            keyalgorithm=self.cfg.tsig_algorithm,
        )

    def _send(self, update, what):
        c = self.cfg
        if c.dns_dry_run:
            log.warning("DRY RUN, not sending: %s", what)
            return
        try:
            response = dns.query.tcp(update, c.dns_server, port=c.dns_port, timeout=5)
        except (dns.exception.DNSException, OSError) as exc:
            raise DnsError(f"Could not reach DNS server {c.dns_server}: {exc}") from exc
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            raise DnsError(f"DNS server refused the update ({dns.rcode.to_text(rcode)}) for {what}")
        log.info("DNS update OK: %s", what)

    def publish(self, name, tld, ip):
        """Create or replace the A record (and the www alias) for a domain."""
        fqdn = f"{name}.{tld}."
        u = self._new_update(tld)
        u.replace(fqdn, self.cfg.ttl, "A", ip)
        u.replace("www." + fqdn, self.cfg.ttl, "CNAME", fqdn)
        self._send(u, f"{fqdn} A {ip}")

    def unpublish(self, name, tld, labels=()):
        """Remove a domain from DNS: the apex A, the www alias and any student subdomains (by label)."""
        fqdn = f"{name}.{tld}."
        u = self._new_update(tld)
        u.delete(fqdn, "A")
        u.delete("www." + fqdn, "CNAME")
        for label in labels:
            u.delete(f"{label}.{fqdn}", "A")
            u.delete(f"{label}.{fqdn}", "CNAME")
        self._send(u, f"delete {fqdn}" + (f" (+{len(labels)} subdomains)" if labels else ""))

    def set_record(self, name, tld, label, rtype, value):
        """Create or replace a subdomain. Done in ONE update message, so there is never a moment
        with both an A and a CNAME at the same name."""
        sub = f"{label}.{name}.{tld}."
        u = self._new_update(tld)
        u.delete(sub, "A")
        u.delete(sub, "CNAME")
        if rtype == "A":
            u.add(sub, self.cfg.ttl, "A", value)
        elif rtype == "CNAME":
            u.add(sub, self.cfg.ttl, "CNAME", value.rstrip(".") + ".")
        else:
            raise DnsError(f"Unsupported record type {rtype!r}")
        self._send(u, f"{sub} {rtype} {value}")

    def remove_record(self, name, tld, label):
        sub = f"{label}.{name}.{tld}."
        u = self._new_update(tld)
        u.delete(sub, "A")
        u.delete(sub, "CNAME")
        self._send(u, f"delete {sub}")

    def publish_all(self, name, tld, ip, records=()):
        """(Re)send a domain and all its subdomains. Used by the admin re-sync."""
        self.publish(name, tld, ip)
        for r in records:
            self.set_record(name, tld, r["label"], r["rtype"], r["value"])

    def lookup(self, name, tld, label=None):
        """Ask the DNS server what it currently answers for this name (A records; a CNAME is followed)."""
        fqdn = f"{label}.{name}.{tld}." if label else f"{name}.{tld}."
        c = self.cfg
        if c.dns_dry_run:
            return ["(dry run)"]
        q = dns.message.make_query(fqdn, "A")
        try:
            r = dns.query.udp(q, c.dns_server, port=c.dns_port, timeout=3)
        except (dns.exception.DNSException, OSError) as exc:
            raise DnsError(f"Could not reach DNS server {c.dns_server}: {exc}") from exc
        out = []
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.A:
                out += [rd.address for rd in rrset]
        return out
