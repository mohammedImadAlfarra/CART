"""The vulnerable lab: four small sites, each focused on one attack family.

Each `make_*` factory returns a fresh Flask app bound to its own in-memory
state, so all targets can run at once (one port each). Ground truth for every
site lives in registry.py.

ALL targets are deliberately vulnerable practice apps and must stay on
localhost only.
"""
from __future__ import annotations

import html
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, redirect, request, session

from .common import fixes_reader, plant_canary, shell


# =============================================================== 1) BANK : SQL injection
def make_bank(fixes_path: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("bank")
    app.secret_key = secrets.token_hex(8)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, balance REAL);"
        "INSERT INTO users VALUES(1,'admin','B4nk-Adm1n!','admin',100000),"
        "(2,'sara','sara2024','user',1500),(3,'omar','omar2024','user',300);"
    )
    nav = [("Login", "/login"), ("Accounts", "/accounts?holder=sara")]

    @app.route("/")
    def index():
        who = session.get("user")
        extra = f"<p>Signed in as {html.escape(who['username'])} ({who['role']}).</p>" if who else ""
        return shell("<p>MicroBank online banking.</p>" + extra, "MicroBank", nav)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return shell("<form method='post'><input name='username'>"
                         "<input name='password' type='password'><button>Login</button></form>", "MicroBank", nav)
        u, p = request.form.get("username", ""), request.form.get("password", "")
        try:
            if fixed("sqli_login"):
                row = db.execute("SELECT id,username,role FROM users WHERE username=? AND password=?",
                                 (u, p)).fetchone()
            else:
                row = db.execute(f"SELECT id,username,role FROM users WHERE username='{u}' AND password='{p}'"
                                 ).fetchone()
        except sqlite3.Error as e:
            return shell(f"<p>DB error: {html.escape(str(e))}</p>", "MicroBank", nav), 500
        if not row:
            return shell("<p>Invalid credentials</p>", "MicroBank", nav), 401
        session["user"] = {"id": row[0], "username": row[1], "role": row[2]}
        return redirect("/")

    @app.route("/accounts")
    def accounts():
        holder = request.args.get("holder", "")
        try:
            if fixed("sqli_search"):
                rows = db.execute("SELECT username,balance FROM users WHERE username LIKE ?",
                                  (f"%{holder}%",)).fetchall()
            else:
                rows = db.execute(f"SELECT username,balance FROM users WHERE username LIKE '%{holder}%'").fetchall()
        except sqlite3.Error as e:
            return shell(f"<p>DB error: {html.escape(str(e))}</p>", "MicroBank", nav), 500
        items = "".join(f"<li>{html.escape(u)}: balance hidden</li>" for u, _ in rows)
        return shell(f"<p>Accounts matching {html.escape(holder)}:</p><ul>{items}</ul>"
                     f"<p>{len(rows)} match(es)</p>", "MicroBank", nav)

    return app


# =============================================================== 2) BLOG : XSS
def make_blog(fixes_path: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("blog")
    nav = [("Search", "/search?q=hello"), ("Greet", "/hello?name=world")]

    @app.route("/")
    def index():
        return shell("<p>DevBlog - thoughts on code.</p>", "DevBlog", nav)

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        shown = html.escape(q) if fixed("xss_search") else q
        return shell(f"<p>You searched for: {shown}</p><p>No posts found.</p>", "DevBlog", nav)

    @app.route("/comment")  # NOT linked from any page -> link-based recon cannot find it
    def comment():
        text = request.args.get("text", "")
        shown = html.escape(text) if fixed("xss_comment") else text
        return shell(f"<h3>Preview</h3><div class='comment'>{shown}</div>", "DevBlog", nav)

    @app.route("/hello")  # decoy: safely escaped
    def hello():
        return shell(f"<p>Hello {html.escape(request.args.get('name', ''))}!</p>", "DevBlog", nav)

    return app


# =============================================================== 3) FILES : path traversal
def make_files(fixes_path: Path, base_dir: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("files")
    files_dir = base_dir / "public"
    files_dir.mkdir(parents=True, exist_ok=True)
    (files_dir / "readme.txt").write_text("CloudFiles public readme\n", encoding="utf-8")
    (files_dir / "logo.txt").write_text("[logo]\n", encoding="utf-8")
    plant_canary(base_dir / "private")
    nav = [("Readme", "/download?file=readme.txt"), ("Docs", "/view?page=faq")]

    @app.route("/")
    def index():
        return shell("<p>CloudFiles document portal.</p>", "CloudFiles", nav)

    @app.route("/download")
    def download():
        name = request.args.get("file", "")
        if fixed("path_traversal"):
            target = (files_dir / name).resolve()
            if files_dir.resolve() not in target.parents:
                abort(403)
        else:
            target = Path(os.path.join(files_dir, name))
        if not target.is_file():
            abort(404)
        return target.read_text(encoding="utf-8", errors="replace"), 200, {"Content-Type": "text/plain"}

    @app.route("/view")  # decoy: whitelist
    def view():
        pages = {"faq": "Frequently asked questions", "help": "Help center"}
        return shell(f"<p>{html.escape(pages.get(request.args.get('page', ''), 'Unknown page'))}</p>",
                     "CloudFiles", nav)

    return app


# =============================================================== 4) CLEAN : no vulns (false-positive test)
def make_clean(fixes_path: Path) -> Flask:
    app = Flask("clean")
    nav = [("Search", "/search?q=hi"), ("Profile", "/profile?id=1")]
    names = {1: "Team", 2: "About"}

    @app.route("/")
    def index():
        return shell("<p>SecureCorp - we take security seriously.</p>", "SecureCorp", nav)

    @app.route("/search")
    def search():  # output is HTML-escaped -> no XSS
        q = request.args.get("q", "")
        return shell(f"<p>Results for {html.escape(q)}: none.</p>", "SecureCorp", nav)

    @app.route("/profile")
    def profile():  # whitelist lookup, no SQL at all -> no injection
        try:
            pid = int(request.args.get("id", "0"))
        except ValueError:
            return shell("<p>Bad id</p>", "SecureCorp", nav), 400
        return shell(f"<p>{html.escape(names.get(pid, 'Unknown'))}</p>", "SecureCorp", nav)

    return app
