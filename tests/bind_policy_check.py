"""Checks what the registrar TSIG key can and cannot do on a LIVE Bind9 (run it after install-bind-config.sh).

    TSIG_SECRET=... DNS_SERVER=10.0.10.25 python3 tests/bind_policy_check.py

It briefly creates and removes foo.beach, and tries to attack the zones; every DENY must be refused."""
import os
import dns.update, dns.query, dns.tsigkeyring, dns.rcode, dns.name
SERVER, PORT = os.environ.get("DNS_SERVER","127.0.0.1"), int(os.environ.get("DNS_PORT","53"))
good = dns.tsigkeyring.from_text({"registrar-key": os.environ["TSIG_SECRET"]})
bad  = dns.tsigkeyring.from_text({"registrar-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
def send(zone, ops, keyring=good):
    kw = dict(keyring=keyring, keyname="registrar-key", keyalgorithm="hmac-sha256") if keyring else {}
    u = dns.update.Update(zone, **kw)
    for op in ops: getattr(u, op[0])(*op[1:])
    try:
        return dns.rcode.to_text(dns.query.tcp(u, SERVER, port=PORT, timeout=5).rcode())
    except Exception as e:
        return type(e).__name__
cases = [
 ("ALLOW  add A   foo.beach",                  "beach.", [("add","foo.beach.",300,"A","10.0.20.5")], good, "NOERROR"),
 ("ALLOW  add CNAME www.foo.beach",            "beach.", [("add","www.foo.beach.",300,"CNAME","foo.beach.")], good, "NOERROR"),
 ("DENY   NS at the apex of beach",            "beach.", [("add","beach.",300,"NS","evil.example.")], good, "REFUSED"),
 ("DENY   A at the apex of beach",             "beach.", [("add","beach.",300,"A","10.9.9.9")], good, "REFUSED"),
 ("DENY   SOA change",                         "beach.", [("replace","beach.",300,"SOA","a. b. 99 1 1 1 1")], good, "REFUSED"),
 ("DENY   TXT at foo.beach",                   "beach.", [("add","foo.beach.",300,"TXT","hi")], good, "REFUSED"),
 ("DENY   MX at foo.beach",                    "beach.", [("add","foo.beach.",300,"MX","10 mail.foo.beach.")], good, "REFUSED"),
 ("DENY   sandbar.lab zone: add record",       "sandbar.lab.", [("add","pwn.sandbar.lab.",300,"A","10.9.9.9")], good, "REFUSED"),
 ("DENY   sandbar.lab zone: replace infra A",  "sandbar.lab.", [("replace","dns-dominica.sandbar.lab.",300,"A","10.9.9.9")], good, "REFUSED"),
 ("DENY   sandbar.lab zone: delete infra A",   "sandbar.lab.", [("delete","registrar.sandbar.lab.","A")], good, "REFUSED"),
 ("DENY   sandbar.lab zone: change NS",        "sandbar.lab.", [("replace","sandbar.lab.",300,"NS","evil.example.")], good, "REFUSED"),
 ("DENY   a 'lab' zone (must not exist)",      "lab.",   [("add","mysite.lab.",300,"A","10.9.9.9")], good, "NOTAUTH"),
 ("DENY   wrong TSIG key",                     "beach.", [("add","evil.beach.",300,"A","10.9.9.9")], bad, "BADSIG"),
 ("DENY   unsigned update",                    "beach.", [("add","evil.beach.",300,"A","10.9.9.9")], None, "REFUSED"),
 ("ALLOW  delete A foo.beach",                 "beach.", [("delete","foo.beach.","A")], good, "NOERROR"),
 ("ALLOW  delete CNAME www.foo.beach",         "beach.", [("delete","www.foo.beach.","CNAME")], good, "NOERROR"),
]
fail = 0
for label, zone, ops, key, want in cases:
    got = send(zone, ops, key)
    ok = got == want or (want == "BADSIG" and got in ("NOTAUTH","BADSIG","PeerBadSignature","PeerBadKey"))
    fail += not ok
    print(("PASS " if ok else "FAIL ") + label.ljust(46), "->", got)
print("failures:", fail)
