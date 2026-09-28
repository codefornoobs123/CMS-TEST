"""CMS web app: admin panel + public site.

Run:  python app.py   then open http://localhost:5000
"""
import hashlib
import hmac
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

import nh3
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from db.init_db import DB_PATH, hash_password

BASE_DIR = Path(__file__).resolve().parent
SECRET_FILE = BASE_DIR / ".secret_key"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
STATUSES = ["draft", "review", "published", "archived"]
ROLE_LEVEL = {"viewer": 0, "author": 1, "editor": 2, "admin": 3}

# Upload types: Pillow image format -> file extension. SVG is deliberately
# excluded because it can carry scripts.
IMAGE_FORMATS = {"JPEG": ".jpg", "PNG": ".png", "GIF": ".gif", "WEBP": ".webp"}
IMAGE_MIME = {".jpg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp"}

# HTML the editor produces; anything else is stripped from page content on save
ALLOWED_TAGS = {"p", "br", "strong", "b", "em", "i", "u", "s", "a", "h1", "h2", "h3", "h4",
                "ul", "ol", "li", "blockquote", "pre", "code", "img", "span", "sub", "sup", "hr"}
ALLOWED_ATTRS = {"a": {"href", "target"}, "img": {"src", "alt", "width", "height"}, "*": {"class"}}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB uploads
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32))
app.secret_key = SECRET_FILE.read_text().strip()


# Database -------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        if not DB_PATH.exists():
            raise RuntimeError("Database not found. Run: python db/init_db.py")
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_settings() -> dict:
    return {r["key"]: r["value"] for r in get_db().execute("SELECT key, value FROM settings")}


# Auth & permissions ---------------------------------------------------------

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    return hmac.compare_digest(check.hex(), digest)


def current_user():
    if "user" not in g:
        uid = session.get("user_id")
        g.user = uid and get_db().execute(
            "SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id "
            "WHERE u.id = ? AND u.is_active = 1", (uid,)).fetchone()
    return g.user


def has_role(min_role: str) -> bool:
    user = current_user()
    return bool(user) and ROLE_LEVEL.get(user["role"], -1) >= ROLE_LEVEL[min_role]


def can_create(post_type: str) -> bool:
    """Editors+ can create anything; authors can create posts only."""
    return has_role("editor") or (has_role("author") and post_type == "post")


def can_edit(post) -> bool:
    """Editors+ can edit anything; authors can edit their own posts."""
    if has_role("editor"):
        return True
    return has_role("author") and post["type"] == "post" and post["author_id"] == current_user()["id"]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(min_role: str):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not has_role(min_role):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# CSRF protection for every form post
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf_token")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not token or not hmac.compare_digest(token, sent):
            abort(400, "Invalid form token. Go back, refresh the page and try again.")


@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return {"csrf_token": session["csrf_token"], "user": current_user(),
            "has_role": has_role, "can_edit": can_edit, "can_create": can_create,
            "media_url": media_url}


# Helpers --------------------------------------------------------------------

def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "untitled"


def unique_slug(slug: str, post_type: str, exclude_id=None) -> str:
    db, candidate, n = get_db(), slug, 2
    while db.execute("SELECT 1 FROM posts WHERE type = ? AND slug = ? AND id IS NOT ?",
                     (post_type, candidate, exclude_id)).fetchone():
        candidate, n = f"{slug}-{n}", n + 1
    return candidate


def clean_html(html: str) -> str:
    return nh3.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS,
                     url_schemes={"http", "https", "mailto", "tel"})


def safe_url(url: str) -> bool:
    """Menu links: only site-relative paths or http(s)/mailto/tel URLs."""
    return bool(re.match(r"^(/(?!/)|https?://|mailto:|tel:)", url or ""))


def media_url(item) -> str:
    return url_for("static", filename=item["path"])


def save_upload(file):
    """Validate and store an uploaded file. Returns (media_id, error)."""
    if not file or not file.filename:
        return None, "No file chosen."
    stem = Path(secure_filename(file.filename)).stem[:60] or "file"
    head = file.stream.read(5)
    file.stream.seek(0)
    width = height = None

    if head == b"%PDF-":
        ext, mime = ".pdf", "application/pdf"
    else:
        try:
            with Image.open(file.stream) as img:
                fmt, (width, height) = img.format, img.size
                img.verify()
        except (UnidentifiedImageError, OSError, SyntaxError):
            return None, "That file isn't a supported image (JPG, PNG, GIF, WebP) or PDF."
        if fmt not in IMAGE_FORMATS:
            return None, f"{fmt} images aren't supported. Use JPG, PNG, GIF or WebP."
        ext = IMAGE_FORMATS[fmt]
        mime = IMAGE_MIME[ext]
        file.stream.seek(0)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{stem}-{secrets.token_hex(4)}{ext}"
    file.save(UPLOAD_DIR / name)
    size = (UPLOAD_DIR / name).stat().st_size
    media_id = get_db().execute(
        "INSERT INTO media (filename, path, mime_type, size_bytes, width, height, alt_text, uploaded_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (file.filename, f"uploads/{name}", mime, size, width, height,
         stem.replace("-", " ").replace("_", " "), current_user()["id"])).lastrowid
    get_db().commit()
    return media_id, None


# Login / account ------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("email", "").strip()
        row = get_db().execute(
            "SELECT * FROM users WHERE (email = ? OR username = ?) AND is_active = 1",
            (ident, ident)).fetchone()
        if row and verify_password(request.form.get("password", ""), row["password_hash"]):
            session.clear()
            session["user_id"] = row["id"]
            get_db().execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", (row["id"],))
            get_db().commit()
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Wrong email or password.", "error")
    return render_template("admin/login.html")


@app.route("/admin/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        user = current_user()
        new = request.form.get("new_password", "")
        if not verify_password(request.form.get("current_password", ""), user["password_hash"]):
            flash("Current password is wrong.", "error")
        elif len(new) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new != request.form.get("confirm_password"):
            flash("New passwords don't match.", "error")
        else:
            get_db().execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user["id"]))
            get_db().commit()
            flash("Password changed.", "ok")
            return redirect(url_for("account"))
    return render_template("admin/account.html")


# Pages & posts --------------------------------------------------------------

@app.route("/admin/")
@login_required
def dashboard():
    post_type = request.args.get("type", "page")
    if post_type not in ("page", "post"):
        post_type = "page"
    items = get_db().execute(
        "SELECT p.*, u.display_name AS author FROM posts p JOIN users u ON u.id = p.author_id "
        "WHERE p.type = ? ORDER BY p.updated_at DESC", (post_type,)).fetchall()
    counts = dict(get_db().execute("SELECT type, COUNT(*) FROM posts GROUP BY type").fetchall())
    return render_template("admin/dashboard.html", items=items, post_type=post_type, counts=counts)


@app.route("/admin/new/<post_type>", methods=["GET", "POST"])
@app.route("/admin/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit(post_type=None, post_id=None):
    db = get_db()
    post = None
    if post_id:
        post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone() or abort(404)
        post_type = post["type"]
        if not can_edit(post):
            abort(403)
    elif post_type not in ("page", "post"):
        abort(404)
    elif not can_create(post_type):
        abort(403)

    images = db.execute("SELECT * FROM media WHERE mime_type LIKE 'image/%' ORDER BY id DESC").fetchall()

    if request.method == "POST":
        f = request.form
        title = f.get("title", "").strip()
        status = f.get("status") if f.get("status") in STATUSES else "draft"
        featured = f.get("featured_image_id", type=int)
        if featured and not db.execute("SELECT 1 FROM media WHERE id = ?", (featured,)).fetchone():
            featured = None
        if not title:
            flash("Title is required.", "error")
            return render_template("admin/edit.html", post=f, post_id=post_id, post_type=post_type,
                                   statuses=STATUSES, images=images)

        slug = unique_slug(slugify(f.get("slug") or title), post_type, post_id)
        values = (title, slug, f.get("excerpt", ""), clean_html(f.get("body", "")), status,
                  f.get("meta_title", ""), f.get("meta_description", ""), featured)

        if post:
            db.execute("INSERT INTO post_revisions (post_id, title, body, edited_by) VALUES (?, ?, ?, ?)",
                       (post["id"], post["title"], post["body"], current_user()["id"]))
            db.execute("UPDATE posts SET title=?, slug=?, excerpt=?, body=?, status=?, meta_title=?, "
                       "meta_description=?, featured_image_id=?, updated_at=datetime('now'), "
                       "published_at = CASE WHEN ? = 'published' AND published_at IS NULL "
                       "THEN datetime('now') ELSE published_at END WHERE id=?",
                       (*values, status, post["id"]))
            new_id = post["id"]
        else:
            new_id = db.execute(
                "INSERT INTO posts (title, slug, excerpt, body, status, meta_title, meta_description, "
                "featured_image_id, type, author_id, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "CASE WHEN ? = 'published' THEN datetime('now') END)",
                (*values, post_type, current_user()["id"], status)).lastrowid
        db.commit()
        flash("Saved.", "ok")
        return redirect(url_for("edit", post_id=new_id))

    revisions = post and db.execute(
        "SELECT r.created_at, u.display_name FROM post_revisions r LEFT JOIN users u ON u.id = r.edited_by "
        "WHERE r.post_id = ? ORDER BY r.id DESC LIMIT 10", (post["id"],)).fetchall()
    return render_template("admin/edit.html", post=post, post_id=post_id, post_type=post_type,
                           statuses=STATUSES, revisions=revisions, images=images)


@app.route("/admin/delete/<int:post_id>", methods=["POST"])
@login_required
def delete(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone() or abort(404)
    if not can_edit(post):
        abort(403)
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash(f"Deleted “{post['title']}”.", "ok")
    return redirect(url_for("dashboard", type=post["type"]))


# Media library --------------------------------------------------------------

@app.route("/admin/media")
@login_required
def media():
    items = get_db().execute(
        "SELECT m.*, u.display_name AS uploader FROM media m LEFT JOIN users u ON u.id = m.uploaded_by "
        "ORDER BY m.id DESC").fetchall()
    return render_template("admin/media.html", items=items)


@app.route("/admin/media/upload", methods=["POST"])
@role_required("author")
def media_upload():
    wants_json = request.args.get("format") == "json"
    files = request.files.getlist("file")
    results = [save_upload(f) for f in files] or [(None, "No file chosen.")]

    if wants_json:
        media_id, error = results[0]
        if error:
            return jsonify(error=error), 400
        item = get_db().execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
        return jsonify(id=media_id, url=media_url(item), alt=item["alt_text"])

    ok = sum(1 for mid, _ in results if mid)
    for _, error in results:
        if error:
            flash(error, "error")
    if ok:
        flash(f"Uploaded {ok} file{'s' if ok != 1 else ''}.", "ok")
    return redirect(url_for("media"))


@app.errorhandler(413)
def too_large(_e):
    if request.args.get("format") == "json":
        return jsonify(error="File is too big (max 10 MB)."), 413
    flash("File is too big (max 10 MB).", "error")
    return redirect(url_for("media"))


def editable_media(media_id):
    item = get_db().execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone() or abort(404)
    if not (has_role("editor") or (has_role("author") and item["uploaded_by"] == current_user()["id"])):
        abort(403)
    return item


@app.route("/admin/media/<int:media_id>", methods=["POST"])
@login_required
def media_update(media_id):
    editable_media(media_id)
    get_db().execute("UPDATE media SET alt_text = ?, caption = ? WHERE id = ?",
                     (request.form.get("alt_text", "").strip(), request.form.get("caption", "").strip(), media_id))
    get_db().commit()
    flash("Saved.", "ok")
    return redirect(url_for("media"))


@app.route("/admin/media/<int:media_id>/delete", methods=["POST"])
@login_required
def media_delete(media_id):
    item = editable_media(media_id)
    get_db().execute("DELETE FROM media WHERE id = ?", (media_id,))
    get_db().commit()
    (BASE_DIR / "static" / item["path"]).unlink(missing_ok=True)
    flash(f"Deleted {item['filename']}.", "ok")
    return redirect(url_for("media"))


# Menus ----------------------------------------------------------------------

@app.route("/admin/menus")
@role_required("editor")
def menus():
    db = get_db()
    all_menus = db.execute("SELECT * FROM menus ORDER BY id").fetchall()
    items = db.execute(
        "SELECT i.*, p.title AS post_title, p.status AS post_status FROM menu_items i "
        "LEFT JOIN posts p ON p.id = i.post_id ORDER BY i.menu_id, i.sort_order, i.id").fetchall()
    targets = db.execute("SELECT id, title, type, status FROM posts ORDER BY type, title").fetchall()
    return render_template("admin/menus.html", menus=all_menus, targets=targets,
                           items={m["id"]: [i for i in items if i["menu_id"] == m["id"]] for m in all_menus})


@app.route("/admin/menus/<int:menu_id>/add", methods=["POST"])
@role_required("editor")
def menu_add(menu_id):
    db = get_db()
    db.execute("SELECT 1 FROM menus WHERE id = ?", (menu_id,)).fetchone() or abort(404)
    label = request.form.get("label", "").strip()
    target = request.form.get("target", "")
    url = request.form.get("url", "").strip()
    post_id = None

    if target == "url":
        if not safe_url(url):
            flash("Link must start with /, http://, https://, mailto: or tel:", "error")
            return redirect(url_for("menus"))
    else:
        post = db.execute("SELECT id, title FROM posts WHERE id = ?", (target,)).fetchone()
        if not post:
            flash("Choose a page or enter a link.", "error")
            return redirect(url_for("menus"))
        post_id, url, label = post["id"], None, label or post["title"]

    if not label:
        flash("Label is required.", "error")
        return redirect(url_for("menus"))
    last = db.execute("SELECT COALESCE(MAX(sort_order), 0) FROM menu_items WHERE menu_id = ?", (menu_id,)).fetchone()[0]
    db.execute("INSERT INTO menu_items (menu_id, label, post_id, url, sort_order) VALUES (?, ?, ?, ?, ?)",
               (menu_id, label, post_id, url, last + 1))
    db.commit()
    flash(f"Added “{label}”.", "ok")
    return redirect(url_for("menus"))


@app.route("/admin/menu-items/<int:item_id>/move/<direction>", methods=["POST"])
@role_required("editor")
def menu_move(item_id, direction):
    db = get_db()
    item = db.execute("SELECT * FROM menu_items WHERE id = ?", (item_id,)).fetchone() or abort(404)
    ids = [r[0] for r in db.execute("SELECT id FROM menu_items WHERE menu_id = ? ORDER BY sort_order, id",
                                    (item["menu_id"],))]
    i = ids.index(item_id)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(ids):
        ids[i], ids[j] = ids[j], ids[i]
        db.executemany("UPDATE menu_items SET sort_order = ? WHERE id = ?", [(n, mid) for n, mid in enumerate(ids, 1)])
        db.commit()
    return redirect(url_for("menus"))


@app.route("/admin/menu-items/<int:item_id>/rename", methods=["POST"])
@role_required("editor")
def menu_rename(item_id):
    label = request.form.get("label", "").strip()
    if label:
        get_db().execute("UPDATE menu_items SET label = ? WHERE id = ?", (label, item_id))
        get_db().commit()
    return redirect(url_for("menus"))


@app.route("/admin/menu-items/<int:item_id>/delete", methods=["POST"])
@role_required("editor")
def menu_delete(item_id):
    get_db().execute("DELETE FROM menu_items WHERE id = ?", (item_id,))
    get_db().commit()
    return redirect(url_for("menus"))


# Users ----------------------------------------------------------------------

def active_admin_count(excluding=None) -> int:
    return get_db().execute(
        "SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE r.name = 'admin' AND u.is_active = 1 AND u.id IS NOT ?", (excluding,)).fetchone()[0]


@app.route("/admin/users")
@role_required("admin")
def users():
    rows = get_db().execute(
        "SELECT u.*, r.name AS role, (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id) AS post_count "
        "FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.is_active DESC, u.id").fetchall()
    return render_template("admin/users.html", users=rows)


@app.route("/admin/users/new", methods=["GET", "POST"])
@app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
@role_required("admin")
def user_edit(user_id=None):
    db = get_db()
    target = user_id and (db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() or abort(404))
    roles = db.execute("SELECT * FROM roles ORDER BY id").fetchall()

    if request.method == "POST":
        f = request.form
        email, username = f.get("email", "").strip(), f.get("username", "").strip()
        display_name = f.get("display_name", "").strip() or username
        role = db.execute("SELECT * FROM roles WHERE id = ?", (f.get("role_id", type=int),)).fetchone()
        is_active = 1 if f.get("is_active") else 0
        password = f.get("password", "")
        errors = []

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append("Enter a valid email address.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            errors.append("Username must be 3-30 letters, numbers, dots, dashes or underscores.")
        if not role:
            errors.append("Choose a role.")
        if (not target or password) and len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if db.execute("SELECT 1 FROM users WHERE (email = ? OR username = ?) AND id IS NOT ?",
                      (email, username, user_id)).fetchone():
            errors.append("That email or username is already taken.")
        if target and role and (role["name"] != "admin" or not is_active) and active_admin_count(user_id) == 0:
            errors.append("There must be at least one active admin.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin/user_edit.html", target=f, user_id=user_id, roles=roles)

        if target:
            db.execute("UPDATE users SET email=?, username=?, display_name=?, role_id=?, is_active=? WHERE id=?",
                       (email, username, display_name, role["id"], is_active, user_id))
            if password:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
        else:
            user_id = db.execute(
                "INSERT INTO users (email, username, display_name, role_id, is_active, password_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (email, username, display_name, role["id"], is_active, hash_password(password))).lastrowid
        db.commit()
        flash(f"Saved {display_name}.", "ok")
        return redirect(url_for("users"))

    return render_template("admin/user_edit.html", target=target, user_id=user_id, roles=roles)


# Settings -------------------------------------------------------------------

@app.route("/admin/settings", methods=["GET", "POST"])
@role_required("admin")
def settings():
    db = get_db()
    if request.method == "POST":
        for key in ("site_title", "site_tagline", "homepage_id", "posts_per_page"):
            db.execute("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
                       "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                       (key, request.form.get(key, "").strip()))
        db.commit()
        flash("Settings saved.", "ok")
        return redirect(url_for("settings"))
    pages = db.execute("SELECT id, title FROM posts WHERE type = 'page' ORDER BY title").fetchall()
    return render_template("admin/settings.html", s=get_settings(), pages=pages)


# Public site ----------------------------------------------------------------

def load_menu(location):
    return get_db().execute(
        "SELECT i.label, i.url, p.slug, p.type FROM menu_items i JOIN menus m ON m.id = i.menu_id "
        "LEFT JOIN posts p ON p.id = i.post_id WHERE m.location = ? "
        "AND (p.id IS NULL OR p.status = 'published') ORDER BY i.sort_order, i.id", (location,)).fetchall()


@app.context_processor
def inject_site():
    return {"site": get_settings(), "menu": load_menu("header"), "footer_menu": load_menu("footer")}


def published(post_type, slug):
    return get_db().execute(
        "SELECT p.*, u.display_name AS author, m.path AS image_path, m.alt_text AS image_alt "
        "FROM posts p JOIN users u ON u.id = p.author_id LEFT JOIN media m ON m.id = p.featured_image_id "
        "WHERE p.type = ? AND p.slug = ? AND p.status = 'published'", (post_type, slug)).fetchone()


@app.route("/")
def home():
    home_id = get_settings().get("homepage_id")
    row = home_id and get_db().execute(
        "SELECT slug FROM posts WHERE id = ? AND type = 'page' AND status = 'published'", (home_id,)).fetchone()
    if row:
        return render_template("site/page.html", page=published("page", row["slug"]))
    return redirect(url_for("blog"))


@app.route("/blog/")
def blog():
    per_page = int(get_settings().get("posts_per_page") or 10)
    page_no = max(request.args.get("page", 1, type=int), 1)
    posts = get_db().execute(
        "SELECT p.*, u.display_name AS author, m.path AS image_path, m.alt_text AS image_alt "
        "FROM posts p JOIN users u ON u.id = p.author_id LEFT JOIN media m ON m.id = p.featured_image_id "
        "WHERE p.type = 'post' AND p.status = 'published' ORDER BY p.published_at DESC "
        "LIMIT ? OFFSET ?", (per_page + 1, (page_no - 1) * per_page)).fetchall()
    return render_template("site/blog.html", posts=posts[:per_page], page_no=page_no,
                           has_next=len(posts) > per_page)


@app.route("/blog/<slug>")
def blog_post(slug):
    return render_template("site/page.html", page=published("post", slug) or abort(404))


@app.route("/<slug>")
def page(slug):
    return render_template("site/page.html", page=published("page", slug) or abort(404))


@app.errorhandler(403)
def forbidden(_e):
    return render_template("admin/403.html"), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("site/404.html"), 404


if __name__ == "__main__":
    app.run(debug=True)
