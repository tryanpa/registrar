"""Tests for the registrar.  Run from the repo root:

    python3 -m unittest discover -s tests -v

By default DNS is faked. To run the same flow against a real Bind9:

    LIVE_DNS_SERVER=127.0.0.1 LIVE_DNS_PORT=5300 LIVE_TSIG_SECRET=... python3 -m unittest discover -s tests -v
"""
import ipaddress
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from registrar import create_app                     # noqa: E402
from registrar import validation as v                # noqa: E402
from registrar.config import from_env                # noqa: E402
from registrar.dnsops import Dns, DnsError           # noqa: E402
from registrar.whois_fmt import whois_text           # noqa: E402
from registrar import db as dbm                      # noqa: E402

LIVE = os.environ.get("LIVE_DNS_SERVER")


class FakeDns:
    """Mimics the Dns class. Keys are full names such as 'mysite.beach' or 'blog.mysite.beach'."""

    def __init__(self):
        self.records, self.cnames, self.fail = {}, {}, False

    def _check(self):
        if self.fail:
            raise DnsError("simulated outage")

    def publish(self, name, tld, ip):
        self._check()
        self.records[f"{name}.{tld}"] = ip

    def unpublish(self, name, tld, labels=()):
        self._check()
        self.records.pop(f"{name}.{tld}", None)
        for label in labels:
            self.records.pop(f"{label}.{name}.{tld}", None)
            self.cnames.pop(f"{label}.{name}.{tld}", None)

    def set_record(self, name, tld, label, rtype, value):
        self._check()
        key = f"{label}.{name}.{tld}"
        self.records.pop(key, None)
        self.cnames.pop(key, None)
        (self.records if rtype == "A" else self.cnames)[key] = value

    def remove_record(self, name, tld, label):
        self._check()
        self.records.pop(f"{label}.{name}.{tld}", None)
        self.cnames.pop(f"{label}.{name}.{tld}", None)

    def publish_all(self, name, tld, ip, records=()):
        self.publish(name, tld, ip)
        for r in records:
            self.set_record(name, tld, r["label"], r["rtype"], r["value"])

    def lookup(self, name, tld, label=None):
        key = f"{label}.{name}.{tld}" if label else f"{name}.{tld}"
        if key in self.cnames:                       # follow the alias like a resolver would
            key = self.cnames[key]
        ip = self.records.get(key)
        return [ip] if ip else []


class ValidationTests(unittest.TestCase):
    def test_labels(self):
        for good in ("mysite", "my-site", "abc", "a1b2c3", "x" * 40):
            self.assertIsNone(v.label_error(good), good)
        for bad in ("ab", "x" * 41, "-abc", "abc-", "a--b", "my_site", "my site", "mysite.beach",
                    "MySite", "www", "dns-dominica", "sandbar", "ns1", "a;b", "a\nb", "ünï", "../x",
                    "xn--bad"):
            self.assertIsNotNone(v.label_error(bad), bad)

    def test_ips(self):
        nets = (ipaddress.ip_network("10.0.0.0/8"),)
        self.assertEqual(v.ip_error(" 10.0.20.15 ", nets), ("10.0.20.15", None))
        for bad in ("", "abc", "10.0.20", "10.0.20.256", "8.8.8.8", "127.0.0.1", "0.0.0.0",
                    "224.0.0.1", "::1", "10.0.20.1; rm -rf /", "10.0.20.1\n10.0.20.2", "169.254.1.1"):
            self.assertIsNone(v.ip_error(bad, nets)[0], bad)

    def test_split_domain(self):
        tlds = ("beach",)
        self.assertEqual(v.split_domain("MySite.BEACH", tlds), ("mysite", "beach"))
        self.assertEqual(v.split_domain("http://www.mysite.beach/index.html", tlds), ("mysite", "beach"))
        self.assertEqual(v.split_domain("mysite", tlds), ("mysite", None))
        with self.assertRaises(ValueError):
            v.split_domain("mysite.com", tlds)
        with self.assertRaises(ValueError):
            v.split_domain("a.b.beach", tlds)


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        env = {
            "REGISTRAR_SECRET_KEY": "test-secret", "REGISTRAR_DB": os.path.join(self.tmp.name, "t.db"),
            "DNS_DRY_RUN": "true",
        }
        if LIVE:
            env.update(DNS_SERVER=LIVE, DNS_PORT=os.environ.get("LIVE_DNS_PORT", "53"),
                       TSIG_SECRET=os.environ["LIVE_TSIG_SECRET"], DNS_DRY_RUN="false")
        self.env = env
        self.build_app()
        # make an admin straight in the DB, the same way the CLI does
        from werkzeug.security import generate_password_hash
        c = dbm.connect(self.cfg.db_path)
        c.execute("INSERT INTO users (username, display_name, pw_hash, is_admin, created_at) VALUES ('teacher','Ms. Teacher',?,1,?)",
                  (generate_password_hash("teacherpass"), dbm.utcnow()))
        c.commit()
        c.close()

    def build_app(self, **extra):
        """(Re)create the app with extra settings, keeping the same database."""
        self.cfg = from_env({**self.env, **extra})
        self.dns = Dns(self.cfg) if LIVE else FakeDns()
        self.app = create_app(self.cfg, self.dns)
        self.app.testing = True

    def tearDown(self):
        if LIVE:                                   # leave the real DNS server exactly as we found it
            conn = dbm.connect(self.cfg.db_path)
            for d in conn.execute("SELECT * FROM domains WHERE status='approved'").fetchall():
                labels = [r["label"] for r in conn.execute("SELECT label FROM records WHERE domain_id=?", (d["id"],))]
                self.dns.unpublish(d["name"], d["tld"], labels)
            conn.close()
        self.tmp.cleanup()

    # --- helpers ---
    def client(self):
        return self.app.test_client()

    def token(self, c, path="/login"):
        html = c.get(path, follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, c, path, data=None, token=None):
        data = dict(data or {})
        data["csrf_token"] = token or self.token(c)
        return c.post(path, data=data, follow_redirects=True)

    def signup(self, name="alice", pw="password123"):
        c = self.client()
        r = self.post(c, "/signup", {"username": name, "display_name": name.title() + " Smith",
                                     "password": pw, "password2": pw}, token=self.token(c, "/signup"))
        self.assertIn(b"Welcome aboard", r.data)
        return c

    def teacher(self):
        c = self.client()
        r = self.post(c, "/login", {"username": "teacher", "password": "teacherpass"})
        self.assertIn(b"Admin", r.data)
        return c

    def request_domain(self, c, name="mysite", tld="beach", ip="10.0.20.15"):
        return self.post(c, "/register", {"name": name, "tld": tld, "ip": ip, "purpose": "My first site"})

    def domain_id(self, name, tld):
        c = dbm.connect(self.cfg.db_path)
        row = c.execute("SELECT id FROM domains WHERE name=? AND tld=? AND status IN ('pending','approved')", (name, tld)).fetchone()
        c.close()
        return row["id"]

    # --- tests ---
    def test_search_pages_render(self):
        c = self.client()
        for path in ("/", "/?q=mysite", "/?q=mysite.beach", "/?q=www", "/?q=a", "/?q=bad.com", "/help", "/whois", "/whois?q=x.beach", "/login", "/signup"):
            self.assertEqual(c.get(path).status_code, 200, path)
        body = c.get("/?q=mysite").get_data(as_text=True)
        self.assertIn("Available", body)
        self.assertEqual(body.count('class="result available"'), 1)
        self.assertIn("Reserved", c.get("/?q=sandbar").get_data(as_text=True))

    def test_full_flow_and_dns(self):
        alice, teacher = self.signup(), self.teacher()
        r = self.request_domain(alice)
        self.assertIn(b"Awaiting approval", r.data)
        if not LIVE:
            self.assertNotIn("mysite.beach", self.dns.records)          # not live until approved
        r = teacher.get("/admin")
        self.assertIn(b"mysite", r.data)
        did = self.domain_id("mysite", "beach")
        r = self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        self.assertIn(b"now live in DNS", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach"), ["10.0.20.15"])
        # change IP while live
        r = self.post(alice, f"/domains/{did}/ip", {"ip": "10.0.20.99"}, token=self.token(alice, "/domains"))
        self.assertIn(b"10.0.20.99", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach"), ["10.0.20.99"])
        # whois
        conn = dbm.connect(self.cfg.db_path)
        text = whois_text(self.cfg, conn, "mysite.beach")
        self.assertIn("Domain Name: MYSITE.BEACH", text)
        self.assertIn("Registrant Name: Alice Smith", text)
        self.assertIn("Domain Status: ok", text)
        self.assertNotIn("@", text)
        self.assertIn('No match for "NOPE.BEACH"', whois_text(self.cfg, conn, "nope.beach"))
        self.assertIn("reserved", whois_text(self.cfg, conn, "sandbar.beach"))
        conn.close()
        # release -> gone from DNS, name free again
        r = self.post(alice, f"/domains/{did}/release", token=self.token(alice, "/domains"))
        self.assertIn(b"released", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach"), [])
        self.assertIn(b"Available", alice.get("/?q=mysite").data)

    def test_one_name_per_student_and_uniqueness(self):
        alice, bob = self.signup("alice"), self.signup("bobby")
        self.request_domain(alice, "mysite")
        r = self.request_domain(alice, "another")
        self.assertIn(b"up to 1 name", r.data)
        r = self.request_domain(bob, "mysite")                      # taken by alice
        self.assertIn(b"already taken", r.data)
        r = self.request_domain(bob, "bobsite")
        self.assertIn(b"Awaiting approval", r.data)

    def test_configurable_limit(self):
        self.build_app(MAX_DOMAINS_PER_STUDENT="3")
        alice, teacher = self.signup(), self.teacher()
        for n in ("site-one", "site-two", "site-three"):
            self.assertIn(b"Awaiting approval", self.request_domain(alice, n).data)
        self.assertIn(b"3 of 3 names used", alice.get("/domains").data)
        r = self.request_domain(alice, "site-four")
        self.assertIn(b"up to 3 names", r.data)
        self.assertIn(b"Limit reached", alice.get("/?q=site-four").data)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 3)
        conn.close()
        # approved names count too, and releasing one frees a slot
        did = self.domain_id("site-one", "beach")
        self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        self.assertIn(b"up to 3 names", self.request_domain(alice, "site-four").data)
        self.post(alice, f"/domains/{did}/release", token=self.token(alice, "/domains"))
        self.assertIn(b"Awaiting approval", self.request_domain(alice, "site-four").data)
        # the limit is per student: another student is unaffected
        bob = self.signup("bobby")
        self.assertIn(b"Awaiting approval", self.request_domain(bob, "bob-site").data)

    def test_denied_networks(self):
        nets, denied = (ipaddress.ip_network("10.0.0.0/8"),), (ipaddress.ip_network("10.0.50.0/24"), ipaddress.ip_network("10.0.10.25/32"))
        self.assertEqual(v.ip_error("10.0.20.15", nets, denied), ("10.0.20.15", None))
        self.assertEqual(v.ip_error("10.0.10.26", nets, denied)[1], None)             # neighbour of a /32 is fine
        for bad in ("10.0.10.25", "10.0.50.50", "10.0.50.1", "10.0.50.255"):
            ip, err = v.ip_error(bad, nets, denied)
            self.assertIsNone(ip, bad)
            self.assertIn("infrastructure", err)

    def test_denied_networks_enforced_in_app(self):
        self.build_app(DENIED_NETWORKS="10.0.50.0/24")
        alice = self.signup()
        for bad in ("10.0.50.50", "10.0.50.1"):
            self.assertIn(b"lab infrastructure", self.request_domain(alice, "poop", "beach", bad).data)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        conn.close()
        self.assertIn(b"Awaiting approval", self.request_domain(alice, "poop", "beach", "10.0.20.15").data)
        # changing to a denied address later is refused too, and nothing changes
        did = self.domain_id("poop", "beach")
        r = self.post(alice, f"/domains/{did}/ip", {"ip": "10.0.50.50"}, token=self.token(alice, "/domains"))
        self.assertIn(b"lab infrastructure", r.data)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT ip FROM domains WHERE id=?", (did,)).fetchone()[0], "10.0.20.15")
        conn.close()

    def test_dns_server_address_is_always_denied(self):
        if LIVE:
            self.skipTest("live run uses a loopback DNS server")
        self.build_app(DNS_SERVER="10.0.10.25")                      # no DENIED_NETWORKS set at all
        alice = self.signup()
        self.assertIn(b"lab infrastructure", self.request_domain(alice, "poop", "beach", "10.0.10.25").data)

    def test_bad_denied_networks_setting_is_a_clear_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            from_env({"REGISTRAR_SECRET_KEY": "x", "DENIED_NETWORKS": "10.0.50.0/24, not-a-network"})
        self.assertIn("DENIED_NETWORKS", str(ctx.exception))

    def test_default_limit_is_one(self):
        self.assertEqual(self.cfg.max_domains, 1)
        alice = self.signup()
        self.request_domain(alice, "first")
        self.assertIn(b"up to 1 name.", self.request_domain(alice, "second").data)

    def test_upgrade_drops_old_one_per_tld_index(self):
        import sqlite3
        c = sqlite3.connect(self.cfg.db_path)
        c.execute("CREATE UNIQUE INDEX domains_active_owner_tld ON domains(owner_id, tld) WHERE status IN ('pending','approved')")
        c.commit()
        c.close()
        self.build_app(MAX_DOMAINS_PER_STUDENT="2")          # create_app -> init_db migrates
        c = sqlite3.connect(self.cfg.db_path)
        names = [r[1] for r in c.execute("PRAGMA index_list(domains)")]
        c.close()
        self.assertNotIn("domains_active_owner_tld", names)
        alice = self.signup()
        self.request_domain(alice, "first")
        self.assertIn(b"Awaiting approval", self.request_domain(alice, "second").data)

    def test_lab_and_sandbar_lab_names_are_impossible(self):
        # 1. the registrar refuses to even start if configured to serve them
        for bad in ("lab", "beach,lab", "sandbar.lab", "beach,sandbar.lab"):
            with self.assertRaises(RuntimeError, msg=bad):
                from_env({"REGISTRAR_SECRET_KEY": "x", "TLDS": bad})
        # 2. search, WHOIS and registration all refuse them
        alice = self.signup()
        for q in ("mysite.lab", "mysite.sandbar.lab", "dns-dominica.sandbar.lab", "sandbar.lab"):
            body = alice.get("/?q=" + q).get_data(as_text=True)
            self.assertIn("We only register", body, q)
            self.assertNotIn("Register</a>", body, q)
            self.assertIn("only register", alice.get("/whois?q=" + q).get_data(as_text=True), q)
        for name, tld in (("mysite", "lab"), ("mysite", "sandbar.lab"), ("dns-dominica", "sandbar.lab"), ("sandbar", "lab")):
            self.request_domain(alice, name, tld)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        conn.close()
        # 3. even if the DB were tampered with, the DNS layer will not address a non-student zone
        real = Dns(self.cfg)
        for zone in ("lab", "sandbar.lab"):
            with self.assertRaises(DnsError):
                real.publish("mysite", zone, "10.0.0.5")
            with self.assertRaises(DnsError):
                real.unpublish("mysite", zone)

    def test_bad_input_is_rejected_and_never_stored(self):
        alice = self.signup()
        for name, tld, ip in [("www", "beach", "10.0.0.5"), ("a b", "beach", "10.0.0.5"), ("mysite", "com", "10.0.0.5"),
                              ("mysite", "beach", "8.8.8.8"), ("mysite", "beach", "10.0.0.5; evil"), ("xx", "beach", "10.0.0.5"),
                              ("my_site", "beach", "10.0.0.5"), ("mysite", "beach", "")]:
            self.request_domain(alice, name, tld, ip)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        conn.close()

    def test_rejection_and_revoke(self):
        alice, teacher = self.signup(), self.teacher()
        self.request_domain(alice)
        did = self.domain_id("mysite", "beach")
        r = self.post(teacher, f"/admin/domains/{did}/reject", {"note": "Please pick a cleaner name"}, token=self.token(teacher, "/admin"))
        self.assertIn(b"Rejected", r.data)
        r = alice.get("/domains")
        self.assertIn(b"Rejected", r.data)
        self.assertIn(b"Please pick a cleaner name", r.data)
        # name is free again, and alice may try again
        r = self.request_domain(alice, "mysite2")
        did = self.domain_id("mysite2", "beach")
        self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        r = self.post(teacher, f"/admin/domains/{did}/revoke", {"note": "AUP"}, token=self.token(teacher, "/admin"))
        self.assertIn(b"removed it from DNS", r.data)
        self.assertEqual(self.dns.lookup("mysite2", "beach"), [])

    def test_dns_outage_keeps_request_pending(self):
        if LIVE:
            self.skipTest("needs the fake DNS")
        alice, teacher = self.signup(), self.teacher()
        self.request_domain(alice)
        did = self.domain_id("mysite", "beach")
        self.dns.fail = True
        r = self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        self.assertIn(b"stays pending", r.data)
        conn = dbm.connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT status FROM domains WHERE id=?", (did,)).fetchone()[0], "pending")
        conn.close()

    # ---------------------------------------------------------------- subdomains
    def live_domain(self, name="mysite", ip="10.0.20.15", user="alice"):
        client, teacher = self.signup(user), self.teacher()
        self.request_domain(client, name, "beach", ip)
        did = self.domain_id(name, "beach")
        self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        return client, teacher, did

    def add_rec(self, c, did, label, rtype, value):
        return self.post(c, f"/domains/{did}/records", {"label": label, "rtype": rtype, "value": value},
                         token=self.token(c, "/domains"))

    def rec_count(self):
        conn = dbm.connect(self.cfg.db_path)
        n = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        conn.close()
        return n

    def test_subdomains_a_and_cname(self):
        alice, _, did = self.live_domain()
        r = self.add_rec(alice, did, "blog", "A", "10.0.20.20")
        self.assertIn(b"blog.mysite.beach is live", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach", "blog"), ["10.0.20.20"])
        r = self.add_rec(alice, did, "shop", "CNAME", "mysite.beach")          # alias of the main name
        self.assertIn(b"shop.mysite.beach is live", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach", "shop"), ["10.0.20.15"])
        r = self.add_rec(alice, did, "news", "CNAME", "blog.mysite.beach")     # alias of a subdomain
        self.assertIn(b"news.mysite.beach is live", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach", "news"), ["10.0.20.20"])
        page = alice.get("/domains").get_data(as_text=True)
        self.assertIn("3 of 5 used", page)
        self.assertIn("10.0.20.20", page)
        self.assertEqual(self.dns.lookup("mysite", "beach"), ["10.0.20.15"])   # main name untouched

    def test_subdomain_rules(self):
        self.build_app(DENIED_NETWORKS="10.0.10.25/32")            # same rule in fake and live runs
        alice, _, did = self.live_domain()
        bob_dns_before = dict(getattr(self.dns, "records", {}))
        for label, rtype, value, why in [
            ("www", "A", "10.0.20.20", "www is automatic"),
            ("a", "A", "10.0.20.20", "too short"),
            ("-bad", "A", "10.0.20.20", "hyphen"),
            ("my_blog", "A", "10.0.20.20", "underscore"),
            ("a.b", "A", "10.0.20.20", "dots"),
            ("blog", "A", "8.8.8.8", "outside the lab network"),
            ("blog", "A", "10.0.10.25", "the DNS server"),
            ("blog", "A", "10.0.20.20; evil", "garbage IP"),
            ("blog", "CNAME", "other.beach", "someone else's name"),
            ("blog", "CNAME", "evil.example", "outside .beach"),
            ("blog", "CNAME", "blog.mysite.beach", "alias to itself / nonexistent"),
            ("blog", "CNAME", "x.mysite.beach", "target that doesn't exist"),
            ("blog", "MX", "10.0.20.20", "unsupported type"),
            ("blog", "", "10.0.20.20", "no type"),
        ]:
            self.add_rec(alice, did, label, rtype, value)
            self.assertEqual(self.rec_count(), 0, why)
        if not LIVE:
            self.assertEqual(self.dns.records, bob_dns_before)

    def test_subdomain_duplicates_limit_and_dependencies(self):
        self.build_app(MAX_RECORDS_PER_DOMAIN="2")
        alice, _, did = self.live_domain()
        self.add_rec(alice, did, "blog", "A", "10.0.20.20")
        self.assertIn(b"already exists", self.add_rec(alice, did, "blog", "A", "10.0.20.21").data)
        self.add_rec(alice, did, "shop", "CNAME", "blog.mysite.beach")
        self.assertIn(b"up to 2 subdomains", self.add_rec(alice, did, "more", "A", "10.0.20.22").data)
        self.assertEqual(self.rec_count(), 2)
        self.assertEqual(self.dns.lookup("mysite", "beach", "blog"), ["10.0.20.20"])   # first one unchanged
        # can't remove blog while shop is an alias of it
        conn = dbm.connect(self.cfg.db_path)
        blog_id = conn.execute("SELECT id FROM records WHERE label='blog'").fetchone()[0]
        shop_id = conn.execute("SELECT id FROM records WHERE label='shop'").fetchone()[0]
        conn.close()
        r = self.post(alice, f"/domains/{did}/records/{blog_id}/delete", token=self.token(alice, "/domains"))
        self.assertIn(b"Remove the alias first", r.data)
        self.assertEqual(self.rec_count(), 2)
        self.post(alice, f"/domains/{did}/records/{shop_id}/delete", token=self.token(alice, "/domains"))
        r = self.post(alice, f"/domains/{did}/records/{blog_id}/delete", token=self.token(alice, "/domains"))
        self.assertIn(b"was removed", r.data)
        self.assertEqual(self.rec_count(), 0)
        self.assertEqual(self.dns.lookup("mysite", "beach", "blog"), [])

    def test_subdomains_need_approval_and_ownership(self):
        alice, teacher = self.signup("alice"), self.teacher()
        self.request_domain(alice, "mysite")                       # still pending
        did = self.domain_id("mysite", "beach")
        self.assertIn(b"once your name has been approved", self.add_rec(alice, did, "blog", "A", "10.0.20.20").data)
        self.post(teacher, f"/admin/domains/{did}/approve", token=self.token(teacher, "/admin"))
        bob = self.signup("bobby")
        self.assertEqual(self.add_rec(bob, did, "blog", "A", "10.0.20.20").status_code, 404)   # not bob's domain
        self.assertEqual(self.rec_count(), 0)
        self.add_rec(alice, did, "blog", "A", "10.0.20.20")
        conn = dbm.connect(self.cfg.db_path)
        rid = conn.execute("SELECT id FROM records").fetchone()[0]
        conn.close()
        r = self.post(bob, f"/domains/{did}/records/{rid}/delete", token=self.token(bob, "/domains"))
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.rec_count(), 1)

    def test_dns_outage_keeps_nothing(self):
        if LIVE:
            self.skipTest("needs the fake DNS")
        alice, _, did = self.live_domain()
        self.dns.fail = True
        self.assertIn(b"nothing was changed", self.add_rec(alice, did, "blog", "A", "10.0.20.20").data)
        self.assertEqual(self.rec_count(), 0)

    def test_release_and_revoke_remove_subdomains(self):
        alice, teacher, did = self.live_domain()
        self.add_rec(alice, did, "blog", "A", "10.0.20.20")
        self.add_rec(alice, did, "shop", "CNAME", "mysite.beach")
        self.post(alice, f"/domains/{did}/release", token=self.token(alice, "/domains"))
        self.assertEqual(self.rec_count(), 0)
        for label in ("blog", "shop"):
            self.assertEqual(self.dns.lookup("mysite", "beach", label), [])
        self.assertEqual(self.dns.lookup("mysite", "beach"), [])
        # admin revoke path
        bob, teacher2 = self.signup("bobby"), self.teacher()
        self.request_domain(bob, "bobsite", "beach", "10.0.20.30")
        bid = self.domain_id("bobsite", "beach")
        self.post(teacher2, f"/admin/domains/{bid}/approve", token=self.token(teacher2, "/admin"))
        self.add_rec(bob, bid, "api", "A", "10.0.20.31")
        self.post(teacher2, f"/admin/domains/{bid}/revoke", {"note": "test"}, token=self.token(teacher2, "/admin"))
        self.assertEqual(self.rec_count(), 0)
        self.assertEqual(self.dns.lookup("bobsite", "beach", "api"), [])

    def test_resync_includes_subdomains(self):
        if LIVE:
            self.skipTest("needs the fake DNS")
        alice, teacher, did = self.live_domain()
        self.add_rec(alice, did, "blog", "A", "10.0.20.20")
        self.dns.records.clear()                                   # pretend DNS lost everything
        r = self.post(teacher, "/admin/resync", token=self.token(teacher, "/admin"))
        self.assertIn(b"Re-sent 1 approved", r.data)
        self.assertEqual(self.dns.lookup("mysite", "beach"), ["10.0.20.15"])
        self.assertEqual(self.dns.lookup("mysite", "beach", "blog"), ["10.0.20.20"])

    def test_subdomains_can_be_turned_off(self):
        self.build_app(MAX_RECORDS_PER_DOMAIN="0")
        alice, _, did = self.live_domain()
        self.assertNotIn(b"Add a subdomain", alice.get("/domains").data)
        self.assertIn(b"up to 0 subdomains", self.add_rec(alice, did, "blog", "A", "10.0.20.20").data)
        self.assertEqual(self.rec_count(), 0)

    def test_access_control(self):
        alice, bob = self.signup("alice"), self.signup("bobby")
        self.request_domain(alice)
        did = self.domain_id("mysite", "beach")
        anon = self.client()
        self.assertEqual(anon.get("/admin").status_code, 302)          # -> login
        self.assertEqual(alice.get("/admin").status_code, 403)
        self.assertEqual(alice.get("/admin/users").status_code, 403)
        self.assertEqual(self.post(alice, f"/admin/domains/{did}/approve", token=self.token(alice, "/domains")).status_code, 403)
        # bob cannot change or release alice's domain
        self.assertEqual(self.post(bob, f"/domains/{did}/ip", {"ip": "10.0.0.9"}, token=self.token(bob, "/domains")).status_code, 404)
        self.assertEqual(self.post(bob, f"/domains/{did}/release", token=self.token(bob, "/domains")).status_code, 404)
        self.assertEqual(anon.get("/domains").status_code, 302)

    def test_csrf_enforced(self):
        alice = self.signup()
        r = alice.post("/register", data={"name": "mysite", "tld": "beach", "ip": "10.0.0.5"})
        self.assertEqual(r.status_code, 400)
        r = alice.post("/register", data={"name": "mysite", "tld": "beach", "ip": "10.0.0.5", "csrf_token": "wrong"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client().post("/login", data={"username": "x", "password": "y"}).status_code, 400)

    def test_login_lockout_and_open_redirect(self):
        self.signup("alice")
        c = self.client()
        t = self.token(c)
        for _ in range(5):
            c.post("/login", data={"username": "alice", "password": "nope", "csrf_token": t})
        r = c.post("/login", data={"username": "alice", "password": "password123", "csrf_token": t}, follow_redirects=True)
        self.assertIn(b"Too many failed", r.data)
        from registrar import web
        web._FAILS.clear()
        r = c.post("/login?next=//evil.example/", data={"username": "alice", "password": "password123", "csrf_token": t})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("evil.example", r.headers["Location"])

    def test_xss_is_escaped(self):
        alice = self.signup()
        self.post(alice, "/register", {"name": "mysite", "tld": "beach", "ip": "10.0.0.5", "purpose": "<script>alert(1)</script>"})
        body = alice.get("/domains").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_security_headers(self):
        h = self.client().get("/").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
