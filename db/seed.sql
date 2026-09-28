-- Starter data for the CMS
INSERT INTO roles (id, name, description) VALUES
    (1, 'admin',  'Full access to everything'),
    (2, 'editor', 'Can publish and manage all content'),
    (3, 'author', 'Can write and publish own posts'),
    (4, 'viewer', 'Read-only access to the admin area');

-- The admin password hash is set by init_db.py (default password: "changeme")
INSERT INTO users (id, email, username, password_hash, display_name, role_id) VALUES
    (1, 'admin@example.com', 'admin', '', 'Site Admin', 1);

INSERT INTO categories (id, name, slug, description) VALUES
    (1, 'News',   'news',   'Announcements and updates'),
    (2, 'Guides', 'guides', 'How-to articles');

INSERT INTO tags (id, name, slug) VALUES
    (1, 'Getting Started', 'getting-started'),
    (2, 'Tips',            'tips');

INSERT INTO posts (id, type, title, slug, body, status, author_id, published_at) VALUES
    (1, 'page', 'Home',     'home',     '<h1>Welcome</h1><p>This is the home page.</p>', 'published', 1, datetime('now')),
    (2, 'page', 'About',    'about',    '<p>About us.</p>',                              'published', 1, datetime('now')),
    (3, 'page', 'Contact',  'contact',  '<p>Get in touch.</p>',                          'published', 1, datetime('now')),
    (4, 'post', 'Hello World', 'hello-world', '<p>Your first post. Edit or delete it.</p>', 'published', 1, datetime('now'));

INSERT INTO post_categories (post_id, category_id) VALUES (4, 1);
INSERT INTO post_tags (post_id, tag_id) VALUES (4, 1);

INSERT INTO menus (id, name, location) VALUES
    (1, 'Main Menu', 'header'),
    (2, 'Footer',    'footer');

INSERT INTO menu_items (menu_id, label, post_id, sort_order) VALUES
    (1, 'Home',    1, 1),
    (1, 'About',   2, 2),
    (1, 'Contact', 3, 3),
    (2, 'Contact', 3, 1);

INSERT INTO settings (key, value) VALUES
    ('site_title',       'My Site'),
    ('site_tagline',     'Just another CMS site'),
    ('homepage_id',      '1'),
    ('posts_per_page',   '10'),
    ('comments_enabled', '1'),
    ('timezone',         'Europe/London');
