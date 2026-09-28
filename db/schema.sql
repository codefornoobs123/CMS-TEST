-- CMS database schema (SQLite)
PRAGMA foreign_keys = ON;

-- Users & roles --------------------------------------------------------------

CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,          -- admin, editor, author, viewer
    description TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name  TEXT,
    bio           TEXT,
    avatar_id     INTEGER REFERENCES media(id) ON DELETE SET NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id),
    is_active     INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    last_login_at TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Media library --------------------------------------------------------------

CREATE TABLE IF NOT EXISTS media (
    id          INTEGER PRIMARY KEY,
    filename    TEXT NOT NULL,
    path        TEXT NOT NULL UNIQUE,          -- storage path or URL
    mime_type   TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),
    width       INTEGER,
    height      INTEGER,
    alt_text    TEXT,
    caption     TEXT,
    uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Content --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS posts (
    id                INTEGER PRIMARY KEY,
    type              TEXT NOT NULL DEFAULT 'post' CHECK (type IN ('post', 'page')),
    title             TEXT NOT NULL,
    slug              TEXT NOT NULL,
    excerpt           TEXT,
    body              TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'draft'
                      CHECK (status IN ('draft', 'review', 'scheduled', 'published', 'archived')),
    author_id         INTEGER NOT NULL REFERENCES users(id),
    parent_id         INTEGER REFERENCES posts(id) ON DELETE SET NULL,  -- page hierarchy
    featured_image_id INTEGER REFERENCES media(id) ON DELETE SET NULL,
    meta_title        TEXT,
    meta_description  TEXT,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    allow_comments    INTEGER NOT NULL DEFAULT 1 CHECK (allow_comments IN (0, 1)),
    published_at      TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (type, slug)
);

CREATE INDEX IF NOT EXISTS idx_posts_status_published ON posts(status, published_at);
CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
CREATE INDEX IF NOT EXISTS idx_posts_parent ON posts(parent_id);

-- Every save of a post keeps a snapshot here
CREATE TABLE IF NOT EXISTS post_revisions (
    id         INTEGER PRIMARY KEY,
    post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    edited_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_revisions_post ON post_revisions(post_id, created_at);

-- Taxonomy -------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT,
    parent_id   INTEGER REFERENCES categories(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS tags (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS post_categories (
    post_id     INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, category_id)
);

CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id  INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, tag_id)
);

-- Comments -------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS comments (
    id           INTEGER PRIMARY KEY,
    post_id      INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    parent_id    INTEGER REFERENCES comments(id) ON DELETE CASCADE,  -- threaded replies
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,    -- NULL for guests
    author_name  TEXT,
    author_email TEXT,
    body         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'spam', 'trash')),
    ip_address   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, status);

-- Navigation menus -----------------------------------------------------------

CREATE TABLE IF NOT EXISTS menus (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    location TEXT NOT NULL UNIQUE              -- header, footer, sidebar
);

CREATE TABLE IF NOT EXISTS menu_items (
    id         INTEGER PRIMARY KEY,
    menu_id    INTEGER NOT NULL REFERENCES menus(id) ON DELETE CASCADE,
    parent_id  INTEGER REFERENCES menu_items(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    post_id    INTEGER REFERENCES posts(id) ON DELETE CASCADE,  -- link to a page/post...
    url        TEXT,                                            -- ...or an external URL
    sort_order INTEGER NOT NULL DEFAULT 0,
    CHECK (post_id IS NOT NULL OR url IS NOT NULL)
);

-- Site settings (key/value) --------------------------------------------------

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Keep updated_at current ----------------------------------------------------

CREATE TRIGGER IF NOT EXISTS trg_users_updated AFTER UPDATE ON users
FOR EACH ROW WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_posts_updated AFTER UPDATE ON posts
FOR EACH ROW WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE posts SET updated_at = datetime('now') WHERE id = NEW.id;
END;
