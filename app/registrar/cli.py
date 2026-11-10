"""Admin command line.  Run as:  python3 -m registrar.cli <command>

  create-admin USER     create an instructor account (or promote an existing user)
  set-password USER     reset anyone's password
  resync                re-send every approved domain to the DNS server
  list                  show all active domains
"""
import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash

from . import db as dbm
from . import validation as v
from .config import from_env
from .dnsops import Dns, DnsError


def _password(args):
    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Again: "):
            sys.exit("Passwords do not match.")
    if len(pw) < 8:
        sys.exit("Password must be at least 8 characters.")
    return pw


def main(argv=None):
    p = argparse.ArgumentParser(prog="registrar.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("create-admin", "set-password"):
        s = sub.add_parser(name)
        s.add_argument("username")
        s.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    sub.add_parser("resync")
    sub.add_parser("list")
    args = p.parse_args(argv)

    cfg = from_env()
    dbm.init_db(cfg.db_path)
    conn = dbm.connect(cfg.db_path)

    if args.cmd in ("create-admin", "set-password"):
        username = args.username.lower()
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if args.cmd == "set-password" and not row:
            sys.exit("No such user.")
        if args.cmd == "create-admin" and not row and v.username_error(username):
            sys.exit(v.username_error(username))
        pw = _password(args)
        if row:
            conn.execute("UPDATE users SET pw_hash=?, is_admin=CASE WHEN ?='create-admin' THEN 1 ELSE is_admin END WHERE id=?",
                         (generate_password_hash(pw), args.cmd, row["id"]))
        else:
            conn.execute("INSERT INTO users (username, display_name, pw_hash, is_admin, created_at) VALUES (?,?,?,1,?)",
                         (username, "Instructor", generate_password_hash(pw), dbm.utcnow()))
        dbm.log_event(conn, "cli", args.cmd, username)
        conn.commit()
        print(f"OK: {args.cmd} {username}")
    elif args.cmd == "resync":
        dns, bad = Dns(cfg), 0
        for d in conn.execute("SELECT * FROM domains WHERE status='approved'"):
            try:
                recs = conn.execute("SELECT * FROM records WHERE domain_id=?", (d["id"],)).fetchall()
                dns.publish_all(d["name"], d["tld"], d["ip"], recs)
                print(f"ok    {d['name']}.{d['tld']} -> {d['ip']}" + (f"  (+{len(recs)} subdomains)" if recs else ""))
            except DnsError as exc:
                bad += 1
                print(f"FAIL  {d['name']}.{d['tld']}: {exc}")
        sys.exit(1 if bad else 0)
    elif args.cmd == "list":
        for d in conn.execute("""SELECT d.*, u.username FROM domains d JOIN users u ON u.id=d.owner_id
                                 WHERE d.status IN ('pending','approved') ORDER BY d.tld, d.name"""):
            print(f"{d['status']:9} {d['name']}.{d['tld']:6} {d['ip']:15} {d['username']}")


if __name__ == "__main__":
    main()
