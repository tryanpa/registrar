"""Web routes: public search, student accounts/registrations, admin approval queue."""
import functools
import secrets
import sqlite3
import time

from flask import (Flask, abort, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import db as dbm
from . import validation as v
from .dnsops import DnsError
from .whois_fmt import whois_text

# --- tiny in-memory login throttle (the app runs as one gunicorn worker) -------------
_FAILS = {}
MAX_FAILS, LOCK_SECONDS = 5, 300


def _throttle_key(username):
    return (request.remote_addr, username.lower())


def _locked(key):
    n, until = _FAILS.get(key, (0, 0))
    return n >= MAX_FAILS and time.time() < until


def _record_fail(key):
    n, _ = _FAILS.get(key, (0, 0))
    _FAILS[key] = (n + 1, time.time() + LOCK_SECONDS)


def cfg():
    return current_app.extensions["cfg"]


def dns():
    return current_app.extensions["dns"]


def db():
    if "db" not in g:
        g.db = dbm.connect(cfg().db_path)
    return g.db


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            flash("Please log in first.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if not g.user["is_admin"]:
            abort(403)
        return view(*a, **kw)
    return wrapped


def active_count(user_id):
    return db().execute(
        "SELECT COUNT(*) FROM domains WHERE owner_id=? AND status IN ('pending','approved')", (user_id,)
    ).fetchone()[0]


def limit_message():
    n = cfg().max_domains
    return f"You can hold up to {n} name{'s' if n != 1 else ''}. Release one to register another."


def records_for(domain_id):
    return db().execute("SELECT * FROM records WHERE domain_id=? ORDER BY label", (domain_id,)).fetchall()


def cname_targets(d, records):
    """Names a student's alias may point to: the domain itself, or one of its A-record subdomains."""
    apex = f"{d['name']}.{d['tld']}"
    return [apex] + [f"{r['label']}.{apex}" for r in records if r["rtype"] == "A"]


def availability(name, tld):
    """Status of one name in one TLD for the current user."""
    err = v.label_error(name, cfg().reserved_extra)
    if err:
        return {"tld": tld, "state": "reserved" if v.is_reserved(name, cfg().reserved_extra) else "invalid", "msg": err}
    row = db().execute(
        "SELECT owner_id, status FROM domains WHERE name=? AND tld=? AND status IN ('pending','approved')",
        (name, tld),
    ).fetchone()
    if row:
        mine = g.user is not None and row["owner_id"] == g.user["id"]
        return {"tld": tld, "state": "yours" if mine else "taken", "msg": ""}
    if g.user is not None:
        if active_count(g.user["id"]) >= cfg().max_domains:
            return {"tld": tld, "state": "limit", "msg": limit_message()}
    return {"tld": tld, "state": "available", "msg": ""}


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("my_domains")


def register(app: Flask):
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid:
            row = db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
            if row is None:
                session.clear()
            g.user = row
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Your form expired. Go back, refresh the page and try again.")

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.context_processor
    def inject():
        pending = 0
        if g.get("user") is not None and g.user["is_admin"]:
            pending = db().execute("SELECT COUNT(*) FROM domains WHERE status='pending'").fetchone()[0]
        return {"cfg": cfg(), "csrf_token": csrf_token, "pending_count": pending}

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def error(e):
        return render_template("error.html", e=e), e.code

    # ------------------------------------------------------------------ public pages
    @app.get("/")
    def home():
        q = request.args.get("q", "")
        results, label, error = [], "", None
        if q.strip():
            try:
                label, forced = v.split_domain(q, cfg().tlds)
                if not label:
                    error = "Type the name you'd like to register."
                else:
                    tlds = [forced] if forced else list(cfg().tlds)
                    # always show every TLD so students can compare
                    results = [availability(label, t) for t in cfg().tlds]
                    if forced:
                        results.sort(key=lambda r: r["tld"] != forced)
            except ValueError as exc:
                error = str(exc)
        return render_template("home.html", q=q, label=label, results=results, error=error)

    @app.get("/whois")
    def whois_page():
        q = request.args.get("q", "")
        text = whois_text(cfg(), db(), q) if q.strip() else None
        return render_template("whois.html", q=q, text=text)

    @app.get("/help")
    def help_page():
        return render_template("help.html")

    # ------------------------------------------------------------------ accounts
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if g.user:
            return redirect(url_for("my_domains"))
        form = {}
        if request.method == "POST":
            form = {k: request.form.get(k, "").strip() for k in ("username", "display_name", "email")}
            form["username"] = form["username"].lower()
            pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
            problem = None
            if cfg().signup_code and not secrets.compare_digest(
                    request.form.get("code", "").strip(), cfg().signup_code):
                problem = "That class code isn't right. Ask your instructor."
            elif v.username_error(form["username"]):
                problem = v.username_error(form["username"])
            elif not (2 <= len(form["display_name"]) <= 80):
                problem = "Please enter your name (it appears in WHOIS)."
            elif len(form["email"]) > 120:
                problem = "That email address is too long."
            elif len(pw) < 8:
                problem = "Passwords need at least 8 characters."
            elif pw != pw2:
                problem = "The two passwords don't match."
            if problem:
                flash(problem, "error")
            else:
                try:
                    cur = db().execute(
                        "INSERT INTO users (username, display_name, email, pw_hash, created_at) VALUES (?,?,?,?,?)",
                        (form["username"], form["display_name"], form["email"],
                         generate_password_hash(pw), dbm.utcnow()))
                    dbm.log_event(db(), form["username"], "signup")
                    db().commit()
                except sqlite3.IntegrityError:
                    flash("That username is taken.", "error")
                else:
                    session.clear()
                    session["uid"] = cur.lastrowid
                    session.permanent = True
                    flash("Welcome aboard! Your account is ready.", "success")
                    return redirect(url_for("home"))
        return render_template("signup.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("my_domains"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            key = _throttle_key(username)
            if _locked(key):
                flash("Too many failed attempts. Please wait a few minutes.", "error")
            else:
                row = db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
                if row and check_password_hash(row["pw_hash"], request.form.get("password", "")):
                    _FAILS.pop(key, None)
                    session.clear()
                    session["uid"] = row["id"]
                    session.permanent = True
                    return redirect(safe_next(request.args.get("next")))
                _record_fail(key)
                flash("Wrong username or password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You're logged out.", "info")
        return redirect(url_for("home"))

    # ------------------------------------------------------------------ student: domains
    @app.get("/domains")
    @login_required
    def my_domains():
        rows = db().execute(
            """SELECT * FROM domains WHERE owner_id=? AND status IN ('pending','approved','rejected','revoked')
               ORDER BY CASE status WHEN 'approved' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, created_at DESC""",
            (g.user["id"],)).fetchall()
        recs = {}
        for d in rows:
            if d["status"] == "approved":
                recs[d["id"]] = records_for(d["id"])
        return render_template("domains.html", domains=rows, recs=recs, n_active=active_count(g.user["id"]))

    @app.route("/register", methods=["GET", "POST"])
    @login_required
    def register_domain():
        name = request.values.get("name", "").strip().lower()
        tld = request.values.get("tld", "").strip().lower()
        ip = request.form.get("ip", "").strip()
        purpose = request.form.get("purpose", "").strip()[:120]
        if request.method == "POST":
            problem = None
            if tld not in cfg().tlds:
                problem = "Please choose one of the available TLDs."
            elif v.label_error(name, cfg().reserved_extra):
                problem = v.label_error(name, cfg().reserved_extra)
            ip_clean, ip_problem = v.ip_error(ip, cfg().allowed_nets, cfg().denied_nets)
            if not problem and ip_problem:
                problem = ip_problem
            if not problem:
                state = availability(name, tld)["state"]
                if state in ("taken", "yours"):
                    problem = "Sorry, that name is already taken."
            if problem:
                flash(problem, "error")
            else:
                now = dbm.utcnow()
                try:
                    # check the limit and insert in ONE write transaction, so two quick clicks can't exceed it
                    db().execute("BEGIN IMMEDIATE")
                    if active_count(g.user["id"]) >= cfg().max_domains:
                        db().rollback()
                        flash(limit_message(), "error")
                        return render_template("register.html", name=name, tld=tld, ip=ip, purpose=purpose)
                    db().execute(
                        """INSERT INTO domains (name, tld, owner_id, ip, purpose, status, created_at, updated_at)
                           VALUES (?,?,?,?,?, 'pending', ?, ?)""",
                        (name, tld, g.user["id"], ip_clean, purpose, now, now))
                    dbm.log_event(db(), g.user["username"], "request", f"{name}.{tld} -> {ip_clean}")
                    db().commit()
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash("Someone just registered that name. Please pick another.", "error")
                else:
                    flash(f"Request for {name}.{tld} submitted. Your instructor will review it.", "success")
                    return redirect(url_for("my_domains"))
        return render_template("register.html", name=name, tld=tld, ip=ip, purpose=purpose)

    def _own_domain(domain_id):
        row = db().execute("SELECT * FROM domains WHERE id=? AND owner_id=?", (domain_id, g.user["id"])).fetchone()
        if row is None or row["status"] not in dbm.ACTIVE:
            abort(404)
        return row

    @app.post("/domains/<int:domain_id>/ip")
    @login_required
    def change_ip(domain_id):
        d = _own_domain(domain_id)
        ip_clean, problem = v.ip_error(request.form.get("ip", ""), cfg().allowed_nets, cfg().denied_nets)
        if problem:
            flash(problem, "error")
            return redirect(url_for("my_domains"))
        if d["status"] == "approved":
            try:
                dns().publish(d["name"], d["tld"], ip_clean)
            except DnsError as exc:
                flash(f"DNS update failed, nothing was changed: {exc}", "error")
                return redirect(url_for("my_domains"))
        db().execute("UPDATE domains SET ip=?, updated_at=? WHERE id=?", (ip_clean, dbm.utcnow(), d["id"]))
        dbm.log_event(db(), g.user["username"], "change-ip", f"{d['name']}.{d['tld']} -> {ip_clean}")
        db().commit()
        flash(f"{d['name']}.{d['tld']} now points to {ip_clean}.", "success")
        return redirect(url_for("my_domains"))

    @app.post("/domains/<int:domain_id>/release")
    @login_required
    def release(domain_id):
        d = _own_domain(domain_id)
        if d["status"] == "approved":
            try:
                dns().unpublish(d["name"], d["tld"], [r["label"] for r in records_for(d["id"])])
            except DnsError as exc:
                flash(f"DNS update failed, nothing was changed: {exc}", "error")
                return redirect(url_for("my_domains"))
        db().execute("DELETE FROM records WHERE domain_id=?", (d["id"],))
        db().execute("UPDATE domains SET status='released', updated_at=? WHERE id=?", (dbm.utcnow(), d["id"]))
        dbm.log_event(db(), g.user["username"], "release", f"{d['name']}.{d['tld']}")
        db().commit()
        flash(f"{d['name']}.{d['tld']} has been released.", "info")
        return redirect(url_for("my_domains"))

    # ------------------------------------------------------------------ student: subdomains
    @app.post("/domains/<int:domain_id>/records")
    @login_required
    def add_record(domain_id):
        d = _own_domain(domain_id)
        back = redirect(url_for("my_domains"))
        if d["status"] != "approved":
            flash("You can add subdomains once your name has been approved.", "info")
            return back
        label = request.form.get("label", "").strip().lower()
        rtype = request.form.get("rtype", "")
        value = request.form.get("value", "").strip().lower().rstrip(".")
        problem = v.sub_label_error(label)
        if not problem:
            if rtype == "A":
                value, problem = v.ip_error(value, cfg().allowed_nets, cfg().denied_nets)
            elif rtype == "CNAME":
                if value not in cname_targets(d, records_for(d["id"])):
                    problem = "An alias can only point to your own domain or to one of your subdomains that has an IP address."
            else:
                problem = "Choose a record type."
        if problem:
            flash(problem, "error")
            return back
        fqdn = f"{label}.{d['name']}.{d['tld']}"
        try:
            # limit check, insert and DNS change are one unit: if DNS fails, nothing is kept
            db().execute("BEGIN IMMEDIATE")
            if db().execute("SELECT COUNT(*) FROM records WHERE domain_id=?", (d["id"],)).fetchone()[0] >= cfg().max_records:
                db().rollback()
                flash(f"You can add up to {cfg().max_records} subdomains. Remove one first.", "error")
                return back
            if db().execute("SELECT 1 FROM records WHERE domain_id=? AND label=?", (d["id"], label)).fetchone():
                db().rollback()
                flash(f"{fqdn} already exists. Remove it first if you want to change it.", "error")
                return back
            db().execute("INSERT INTO records (domain_id, label, rtype, value, created_at) VALUES (?,?,?,?,?)",
                         (d["id"], label, rtype, value, dbm.utcnow()))
            try:
                dns().set_record(d["name"], d["tld"], label, rtype, value)
            except DnsError as exc:
                db().rollback()
                flash(f"DNS update failed, nothing was changed: {exc}", "error")
                return back
            dbm.log_event(db(), g.user["username"], "add-record", f"{fqdn} {rtype} {value}")
            db().commit()
        except sqlite3.OperationalError:
            db().rollback()
            flash("The registrar is busy, please try again.", "error")
            return back
        flash(f"{fqdn} is live.", "success")
        return back

    @app.post("/domains/<int:domain_id>/records/<int:record_id>/delete")
    @login_required
    def delete_record(domain_id, record_id):
        d = _own_domain(domain_id)
        rec = db().execute("SELECT * FROM records WHERE id=? AND domain_id=?", (record_id, d["id"])).fetchone()
        if rec is None:
            abort(404)
        fqdn = f"{rec['label']}.{d['name']}.{d['tld']}"
        if rec["rtype"] == "A":
            dependents = db().execute("SELECT label FROM records WHERE domain_id=? AND rtype='CNAME' AND value=?",
                                      (d["id"], fqdn)).fetchall()
            if dependents:
                names = ", ".join(r["label"] + "." + d["name"] + "." + d["tld"] for r in dependents)
                flash(f"Remove the alias first: {names} points to {fqdn}.", "error")
                return redirect(url_for("my_domains"))
        try:
            dns().remove_record(d["name"], d["tld"], rec["label"])
        except DnsError as exc:
            flash(f"DNS update failed, nothing was changed: {exc}", "error")
            return redirect(url_for("my_domains"))
        db().execute("DELETE FROM records WHERE id=?", (rec["id"],))
        dbm.log_event(db(), g.user["username"], "remove-record", fqdn)
        db().commit()
        flash(f"{fqdn} was removed.", "info")
        return redirect(url_for("my_domains"))

    # ------------------------------------------------------------------ admin
    @app.get("/admin")
    @admin_required
    def admin_home():
        pending = db().execute(
            """SELECT d.*, u.username, u.display_name FROM domains d JOIN users u ON u.id=d.owner_id
               WHERE d.status='pending' ORDER BY d.created_at""").fetchall()
        counts = {r["status"]: r["n"] for r in db().execute(
            "SELECT status, COUNT(*) n FROM domains GROUP BY status")}
        users = db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
        events = db().execute("SELECT * FROM events ORDER BY id DESC LIMIT 15").fetchall()
        return render_template("admin.html", pending=pending, counts=counts, users=users, events=events)

    @app.get("/admin/domains")
    @admin_required
    def admin_domains():
        status = request.args.get("status", "")
        q = v.clean_query(request.args.get("q", ""))
        sql = """SELECT d.*, u.username, u.display_name FROM domains d JOIN users u ON u.id=d.owner_id WHERE 1=1"""
        args = []
        if status:
            sql += " AND d.status=?"
            args.append(status)
        if q:
            sql += " AND (d.name LIKE ? OR u.username LIKE ? OR d.ip LIKE ?)"
            args += [f"%{q}%"] * 3
        rows = db().execute(sql + " ORDER BY d.created_at DESC LIMIT 500", args).fetchall()
        return render_template("admin_domains.html", domains=rows, status=status, q=q)

    @app.get("/admin/users")
    @admin_required
    def admin_users():
        rows = db().execute(
            """SELECT u.*, (SELECT COUNT(*) FROM domains d WHERE d.owner_id=u.id AND d.status IN ('pending','approved')) AS n
               FROM users u ORDER BY u.created_at DESC""").fetchall()
        return render_template("admin_users.html", users=rows)

    def _domain(domain_id):
        row = db().execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
        if row is None:
            abort(404)
        return row

    def _back():
        return redirect(request.form.get("back") if (request.form.get("back") or "").startswith("/admin") else url_for("admin_home"))

    @app.post("/admin/domains/<int:domain_id>/approve")
    @admin_required
    def admin_approve(domain_id):
        d = _domain(domain_id)
        if d["status"] != "pending":
            flash("That request is no longer pending.", "info")
            return _back()
        try:
            dns().publish(d["name"], d["tld"], d["ip"])
        except DnsError as exc:
            flash(f"DNS update failed, so the request stays pending: {exc}", "error")
            return _back()
        now = dbm.utcnow()
        db().execute("UPDATE domains SET status='approved', decided_at=?, updated_at=?, decided_by=?, admin_note='' WHERE id=?",
                     (now, now, g.user["username"], d["id"]))
        dbm.log_event(db(), g.user["username"], "approve", f"{d['name']}.{d['tld']} -> {d['ip']}")
        db().commit()
        flash(f"Approved {d['name']}.{d['tld']}. It is now live in DNS.", "success")
        return _back()

    @app.post("/admin/domains/<int:domain_id>/reject")
    @admin_required
    def admin_reject(domain_id):
        d = _domain(domain_id)
        if d["status"] != "pending":
            flash("That request is no longer pending.", "info")
            return _back()
        now = dbm.utcnow()
        db().execute("UPDATE domains SET status='rejected', decided_at=?, updated_at=?, decided_by=?, admin_note=? WHERE id=?",
                     (now, now, g.user["username"], request.form.get("note", "").strip()[:200], d["id"]))
        dbm.log_event(db(), g.user["username"], "reject", f"{d['name']}.{d['tld']}")
        db().commit()
        flash(f"Rejected {d['name']}.{d['tld']}.", "info")
        return _back()

    @app.post("/admin/domains/<int:domain_id>/revoke")
    @admin_required
    def admin_revoke(domain_id):
        d = _domain(domain_id)
        if d["status"] not in dbm.ACTIVE:
            flash("That domain isn't active.", "info")
            return _back()
        if d["status"] == "approved":
            try:
                dns().unpublish(d["name"], d["tld"], [r["label"] for r in records_for(d["id"])])
            except DnsError as exc:
                flash(f"DNS update failed, nothing was changed: {exc}", "error")
                return _back()
        db().execute("DELETE FROM records WHERE domain_id=?", (d["id"],))
        now = dbm.utcnow()
        db().execute("UPDATE domains SET status='revoked', updated_at=?, decided_by=?, admin_note=? WHERE id=?",
                     (now, g.user["username"], request.form.get("note", "").strip()[:200], d["id"]))
        dbm.log_event(db(), g.user["username"], "revoke", f"{d['name']}.{d['tld']}")
        db().commit()
        flash(f"Revoked {d['name']}.{d['tld']} and removed it from DNS.", "info")
        return _back()

    @app.post("/admin/domains/<int:domain_id>/check")
    @admin_required
    def admin_check(domain_id):
        d = _domain(domain_id)
        try:
            answers = dns().lookup(d["name"], d["tld"])
        except DnsError as exc:
            flash(str(exc), "error")
            return _back()
        fqdn = f"{d['name']}.{d['tld']}"
        if d["status"] == "approved":
            ok = answers == [d["ip"]]
            flash(f"DNS says {fqdn} = {', '.join(answers) or 'nothing'} (expected {d['ip']}).", "success" if ok else "error")
        else:
            flash(f"DNS says {fqdn} = {', '.join(answers) or 'nothing'}.", "info")
        return _back()

    @app.post("/admin/resync")
    @admin_required
    def admin_resync():
        rows = db().execute("SELECT * FROM domains WHERE status='approved'").fetchall()
        failed = []
        for d in rows:
            try:
                dns().publish_all(d["name"], d["tld"], d["ip"], records_for(d["id"]))
            except DnsError as exc:
                failed.append(f"{d['name']}.{d['tld']}: {exc}")
        dbm.log_event(db(), g.user["username"], "resync", f"{len(rows) - len(failed)}/{len(rows)} ok")
        db().commit()
        if failed:
            flash("Some records failed: " + "; ".join(failed[:3]), "error")
        else:
            flash(f"Re-sent {len(rows)} approved domain(s) to DNS.", "success")
        return redirect(url_for("admin_home"))
