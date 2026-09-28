"""End-to-end tests. Runs against a temporary copy of the database.

Run:  python tests/test_app.py
"""
import io
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import app as appmod  # noqa: E402

tmp = Path(tempfile.mkdtemp()) / "test.db"
shutil.copy(ROOT / "db" / "cms.db", tmp)
appmod.DB_PATH = tmp
app = appmod.app
db = sqlite3.connect(tmp)
db.row_factory = sqlite3.Row
uploads_before = set((ROOT / "static" / "uploads").glob("*"))
fails = 0


def check(label, cond):
    global fails
    fails += not cond
    print(("PASS " if cond else "FAIL ") + label)


def token(c, path="/admin/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


def client(ident, pw):
    c = app.test_client()
    r = c.post("/admin/login", data={"email": ident, "password": pw, "csrf_token": token(c)})
    if r.status_code != 302:
        return c, None, False
    return c, token(c, "/admin/account"), True  # login issues a fresh CSRF token


def png(w=40, h=30):
    b = io.BytesIO()
    Image.new("RGB", (w, h), "red").save(b, "PNG")
    b.seek(0)
    return b


def upload(c, t, file, name, json=False):
    url = "/admin/media/upload" + ("?format=json" if json else "")
    return c.post(url, data={"csrf_token": t, "file": (file, name)}, content_type="multipart/form-data")


try:
    admin, t, ok = client("admin", "changeme")
    check("admin login", ok)

    for p in ["/admin/", "/admin/media", "/admin/menus", "/admin/users", "/admin/users/new",
              "/admin/edit/1", "/admin/new/post", "/admin/settings", "/admin/account"]:
        r = admin.get(p)
        check(f"GET {p} -> {r.status_code}", r.status_code == 200)

    # Media
    r = upload(admin, t, png(), "My Photo.png")
    check("upload png", r.status_code == 302 and b"Uploaded 1 file" in admin.get("/admin/media").data)
    def media_count():
        return db.execute("select count(*) from media").fetchone()[0]

    n = media_count()
    upload(admin, t, io.BytesIO(b"<script>alert(1)</script>"), "evil.png")
    check("fake image rejected", media_count() == n and b"a supported image" in admin.get("/admin/media").data)
    upload(admin, t, io.BytesIO(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), "x.svg")
    check("svg rejected", media_count() == n)
    upload(admin, t, io.BytesIO(b"%PDF-1.4 test"), "doc.pdf")
    check("pdf accepted", db.execute("select count(*) from media where mime_type='application/pdf'").fetchone()[0] == 1)
    r = admin.post("/admin/media/upload?format=json", data={"file": (png(80, 60), "inline.png")},
                   headers={"X-CSRF-Token": t}, content_type="multipart/form-data")
    j = r.get_json()
    check("editor JSON upload", r.status_code == 200 and j["url"].startswith("/static/uploads/inline-"))
    check("uploaded file served", admin.get(j["url"]).status_code == 200)
    m = db.execute("select * from media where id=?", (j["id"],)).fetchone()
    check("dimensions stored", (m["width"], m["height"]) == (80, 60))
    admin.post(f"/admin/media/{j['id']}", data={"csrf_token": t, "alt_text": "A red box", "caption": "c"})
    check("alt text saved", db.execute("select alt_text from media where id=?", (j["id"],)).fetchone()[0] == "A red box")

    # Post body is sanitised; featured image shows
    body = (f'<h2>Hi</h2><p class="ql-align-center">ok <strong>bold</strong></p><img src="{j["url"]}">'
            '<script>alert(1)</script><a href="javascript:alert(1)">x</a><img src=x onerror=alert(1)>')
    r = admin.post("/admin/new/post", data={"csrf_token": t, "title": "Pic post", "body": body,
                                            "status": "published", "featured_image_id": str(j["id"])})
    pid = int(r.location.rsplit("/", 1)[1])
    saved = db.execute("select body from posts where id=?", (pid,)).fetchone()[0]
    check("script/onerror/javascript stripped", "<script" not in saved and "onerror" not in saved and "javascript:" not in saved)
    check("good html kept", "<h2>Hi</h2>" in saved and 'class="ql-align-center"' in saved and j["url"] in saved)
    pub = admin.get("/blog/pic-post").get_data(as_text=True)
    check("featured image on page", 'class="featured"' in pub and 'alt="A red box"' in pub)
    check("thumbnail on blog list", 'class="thumb"' in admin.get("/blog/").get_data(as_text=True))
    edit_page = admin.get(f"/admin/edit/{pid}").get_data(as_text=True)
    check("editor page loads quill + content as JSON", "quill.js" in edit_page and "const initial = \"\\u003ch2\\u003eHi" in edit_page)

    # Menus
    def labels(menu_id=1):
        return [r[0] for r in db.execute("select label from menu_items where menu_id=? order by sort_order, id", (menu_id,))]

    admin.post("/admin/menus/1/add", data={"csrf_token": t, "target": str(pid), "label": ""})
    check("add post to menu (label defaults to title)", "Pic post" in labels())
    admin.post("/admin/menus/1/add", data={"csrf_token": t, "target": "url", "url": "javascript:alert(1)", "label": "Bad"})
    check("javascript: link rejected", "Bad" not in labels())
    admin.post("/admin/menus/2/add", data={"csrf_token": t, "target": "url", "url": "https://example.com", "label": "Example"})
    check("footer custom link shown", 'href="https://example.com"' in admin.get("/").get_data(as_text=True))
    before = labels()
    item = db.execute("select id from menu_items where menu_id=1 and label='Pic post'").fetchone()[0]
    admin.post(f"/admin/menu-items/{item}/move/up", data={"csrf_token": t})
    after = labels()
    check(f"move up {before} -> {after}", after.index("Pic post") == before.index("Pic post") - 1)
    menus_html = admin.get("/admin/menus").get_data(as_text=True)
    check("first item's up arrow disabled", re.search(r'title="Move up"\s+disabled', menus_html) is not None)
    admin.post(f"/admin/menu-items/{item}/rename", data={"csrf_token": t, "label": "Gallery"})
    check("rename", "Gallery" in labels())
    admin.post(f"/admin/menu-items/{item}/delete", data={"csrf_token": t})
    check("remove", "Gallery" not in labels())
    admin.post("/admin/edit/3", data={"csrf_token": t, "title": "Contact", "slug": "contact", "body": "<p>x</p>", "status": "draft"})
    nav = re.search(r"<nav>.*?</nav>", admin.get("/").get_data(as_text=True), re.S).group(0)
    check("draft page hidden from menu", "Contact" not in nav)

    # Users
    def mk(name, role_id):
        return admin.post("/admin/users/new", data={
            "csrf_token": t, "email": f"{name}@x.com", "username": name, "display_name": name.title(),
            "role_id": str(role_id), "is_active": "1", "password": "password123"})

    check("create editor", mk("eddie", 2).status_code == 302)
    check("create author", mk("amy", 3).status_code == 302)
    check("create author 2", mk("bob", 3).status_code == 302)
    check("create viewer", mk("vic", 4).status_code == 302)
    r = mk("amy", 3)
    check("duplicate username rejected", r.status_code == 200 and b"already taken" in r.data)
    r = admin.post("/admin/users/new", data={"csrf_token": t, "email": "bad", "username": "a", "role_id": "3", "password": "short"})
    check("validation errors", all(s in r.data for s in [b"valid email", b"Username must", b"at least 8"]))
    r = admin.post("/admin/users/1", data={"csrf_token": t, "email": "admin@example.com", "username": "admin", "role_id": "2", "is_active": "1"})
    check("can't demote last admin", b"at least one active admin" in r.data)

    # Role permissions
    ed, et, ok = client("eddie", "password123")
    check("editor login", ok)
    check("editor can edit pages", ed.get("/admin/edit/1").status_code == 200)
    check("editor can manage menus", ed.get("/admin/menus").status_code == 200)
    check("editor blocked from users", ed.get("/admin/users").status_code == 403)
    check("editor blocked from settings", ed.get("/admin/settings").status_code == 403)
    check("editor nav hides Users/Settings", b">Users<" not in ed.get("/admin/").data)

    amy, at, ok = client("amy", "password123")
    check("author login", ok)
    r = amy.post("/admin/new/post", data={"csrf_token": at, "title": "Amy post", "body": "<p>a</p>", "status": "published"})
    amy_pid = int(r.location.rsplit("/", 1)[1])
    check("author creates post", r.status_code == 302)
    check("author can't create page", amy.get("/admin/new/page").status_code == 403)
    check("author can't edit page", amy.get("/admin/edit/1").status_code == 403)
    check("author can't edit admin's post", amy.get(f"/admin/edit/{pid}").status_code == 403)
    check("author can't delete admin's post", amy.post(f"/admin/delete/{pid}", data={"csrf_token": at}).status_code == 403)
    check("author blocked from menus", amy.get("/admin/menus").status_code == 403)
    check("author can upload", upload(amy, at, png(), "amy.png").status_code == 302)
    check("author can't delete admin's media", amy.post(f"/admin/media/{j['id']}/delete", data={"csrf_token": at}).status_code == 403)
    dash = amy.get("/admin/?type=post").get_data(as_text=True)
    check("author sees edit link only on own posts", f'/admin/edit/{pid}"' not in dash and f'/admin/edit/{amy_pid}"' in dash)

    bob, bt, _ = client("bob", "password123")
    check("author can't edit another author's post", bob.get(f"/admin/edit/{amy_pid}").status_code == 403)

    vic, vt, ok = client("vic", "password123")
    check("viewer login", ok)
    check("viewer can view dashboard", vic.get("/admin/").status_code == 200)
    check("viewer can't create post", vic.get("/admin/new/post").status_code == 403)
    check("viewer can't upload", upload(vic, vt, png(), "v.png").status_code == 403)
    check("viewer sees no New button", b"+ New" not in vic.get("/admin/?type=post").data)

    # Deactivation takes effect immediately
    vid = db.execute("select id from users where username='vic'").fetchone()[0]
    admin.post(f"/admin/users/{vid}", data={"csrf_token": t, "email": "vic@x.com", "username": "vic", "role_id": "4"})
    check("deactivated user kicked out", vic.get("/admin/").status_code == 302)
    check("deactivated user can't log in", not client("vic", "password123")[2])
    admin.post(f"/admin/users/{vid}", data={"csrf_token": t, "email": "vic@x.com", "username": "vic",
                                            "role_id": "4", "is_active": "1", "password": "newpassword1"})
    check("reactivate + reset password", client("vic", "newpassword1")[2])

    # Deleting media removes the file and clears featured image
    path = ROOT / "static" / db.execute("select path from media where id=?", (j["id"],)).fetchone()[0]
    admin.post(f"/admin/media/{j['id']}/delete", data={"csrf_token": t})
    check("media delete removes file", not path.exists())
    check("featured image cleared", db.execute("select featured_image_id from posts where id=?", (pid,)).fetchone()[0] is None)
    check("page still renders", admin.get("/blog/pic-post").status_code == 200)
finally:
    db.close()
    for f in set((ROOT / "static" / "uploads").glob("*")) - uploads_before:
        f.unlink()

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
