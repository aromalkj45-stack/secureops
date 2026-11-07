"""ShopEase - hardened version.

Environment variables
  SECRET_KEY          required, >= 32 random characters
  ADMIN_EMAIL / ADMIN_PASSWORD
                      bootstrap (or replace the legacy default) administrator
  COOKIE_SECURE       "1" (default) marks the session cookie Secure (HTTPS only).
                      Set to "0" ONLY for local plain-HTTP development.
  TRUSTED_PROXY_COUNT number of reverse proxies in front of the app (default 0).
                      Needed so rate limiting sees the real client IP.
  DEMO_PAYMENTS       "1" opts into the demo card form for local testing.
                      Defaults to "0"; use a payment provider for real payments.
  CSP                 optional override of the Content-Security-Policy header.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key or len(secret_key) < 32:
    raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters before starting ShopEase.")

SECURE_COOKIES = os.environ.get("COOKIE_SECURE", "1") != "0"
DEMO_PAYMENTS = os.environ.get("DEMO_PAYMENTS", "0") == "1"

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=256 * 1024,  # reject oversized request bodies (413)
)

# When running behind N reverse proxies, trust exactly N hops of X-Forwarded-*.
_proxies = int(os.environ.get("TRUSTED_PROXY_COUNT", "0") or 0)
if _proxies > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxies, x_proto=_proxies)

os.makedirs(app.instance_path, exist_ok=True)
DB_PATH = os.path.join(app.instance_path, "shop.db")

PER_PAGE = 6
TAX_RATE = 0.08
FREE_SHIPPING_OVER = 50.0
SHIPPING_FEE = 5.99
MAX_QTY = 99
MAX_PASSWORD = 128
MIN_PASSWORD = 12
LIMITS = {"name": 100, "email": 254, "phone": 30, "address": 200,
          "city": 100, "zip": 20, "card_name": 100, "q": 100}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
STATUS_STEPS = ["Placed", "Processing", "Shipped", "Out for Delivery", "Delivered"]
ALL_STATUSES = STATUS_STEPS + ["Cancelled"]
OPEN_STATUSES = ("Placed", "Processing")          # can still be cancelled / restocked
TERMINAL_STATUSES = ("Delivered", "Cancelled")    # cannot be changed any more
SORTS = {
    "featured": "id ASC",
    "price_asc": "price ASC",
    "price_desc": "price DESC",
    "rating": "rating DESC",
    "name": "name COLLATE NOCASE ASC",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0,
  auth_version INTEGER NOT NULL DEFAULT 0, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL,
  description TEXT, price REAL NOT NULL, stock INTEGER NOT NULL,
  emoji TEXT, rating REAL DEFAULT 4.0);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, created_at TEXT NOT NULL,
  status TEXT NOT NULL, subtotal REAL, shipping REAL, tax REAL, total REAL,
  ship_name TEXT, ship_address TEXT, ship_city TEXT, ship_zip TEXT, ship_phone TEXT,
  payment TEXT, tracking TEXT, idempotency_key TEXT);
CREATE TABLE IF NOT EXISTS order_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER,
  name TEXT NOT NULL, price REAL NOT NULL, qty INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS request_limits(
  key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_request_limits_window_start ON request_limits(window_start);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor_id INTEGER,
  action TEXT NOT NULL, target TEXT, ip TEXT, detail TEXT);
"""

SEED = [
    ("Wireless Headphones", "Electronics", 79.99, 40, "🎧", 4.6, "Over-ear Bluetooth headphones with 30-hour battery life and active noise reduction.", "wireless-headphones.jpg"),
    ("Smart Watch", "Electronics", 129.00, 25, "⌚", 4.4, "Fitness tracking, heart-rate monitor, sleep analysis and phone notifications.", "smart-watch.jpg"),
    ("Portable Speaker", "Electronics", 49.95, 60, "🔊", 4.3, "Water-resistant Bluetooth speaker with 12 hours of playtime.", "portable-speaker.jpg"),
    ("Mechanical Keyboard", "Electronics", 89.50, 30, "⌨️", 4.7, "Compact hot-swappable keyboard with tactile switches and white backlight.", "mechanical-keyboard.jpg"),
    ("Wireless Mouse", "Electronics", 24.99, 80, "🖱️", 4.2, "Ergonomic silent-click mouse with a USB receiver and 18-month battery.", "wireless-mouse.jpg"),
    ("4K Webcam", "Electronics", 69.00, 20, "📷", 4.1, "Ultra HD webcam with autofocus and dual noise-cancelling microphones.", "webcam.jpg"),
    ("Cotton T-Shirt", "Clothing", 14.99, 150, "👕", 4.3, "Soft 100% combed cotton crew-neck tee in a classic fit.", "cotton-tshirt.jpg"),
    ("Denim Jacket", "Clothing", 59.90, 35, "🧥", 4.5, "Mid-weight denim jacket with button front and chest pockets.", "denim-jacket.jpg"),
    ("Running Shoes", "Clothing", 74.00, 45, "👟", 4.6, "Lightweight breathable running shoes with cushioned midsole.", "running-shoes.jpg"),
    ("Wool Scarf", "Clothing", 19.50, 70, "🧣", 4.0, "Warm merino-blend scarf, 180 cm long, machine washable.", "wool-scarf.jpg"),
    ("Baseball Cap", "Clothing", 12.00, 100, "🧢", 4.1, "Adjustable cotton twill cap with embroidered logo.", "baseball-cap.jpg"),
    ("Leather Wallet", "Clothing", 34.99, 55, "👛", 4.4, "Slim bifold wallet with RFID protection and six card slots.", "leather-wallet.jpg"),
    ("Coffee Maker", "Home & Kitchen", 54.99, 28, "☕", 4.5, "Programmable 12-cup drip coffee maker with reusable filter.", "coffee-maker.jpg"),
    ("Non-Stick Pan Set", "Home & Kitchen", 64.00, 22, "🍳", 4.4, "Three-piece non-stick frying pan set, induction compatible.", "frying-pans.jpg"),
    ("Table Lamp", "Home & Kitchen", 29.99, 48, "💡", 4.2, "Dimmable LED desk lamp with USB charging port.", "table-lamp.jpg"),
    ("Ceramic Mug Set", "Home & Kitchen", 22.50, 90, "🍵", 4.3, "Set of four 350 ml stoneware mugs, dishwasher safe.", "ceramic-mugs.jpg"),
    ("Throw Blanket", "Home & Kitchen", 27.00, 65, "🛋️", 4.6, "Ultra-soft fleece blanket, 130 x 170 cm.", "throw-blanket.jpg"),
    ("Air Purifier", "Home & Kitchen", 119.00, 15, "🌀", 4.5, "HEPA air purifier for rooms up to 40 m² with quiet night mode.", "air-purifier.jpg"),
    ("Mystery Novel", "Books", 11.99, 120, "📕", 4.2, "A gripping paperback mystery that keeps you guessing until the last page.", "mystery-novel.jpg"),
    ("Cooking Basics", "Books", 24.00, 60, "📗", 4.5, "Hardcover guide with 150 simple recipes and step-by-step techniques.", "cookbook.jpg"),
    ("Productivity Handbook", "Books", 16.50, 75, "📘", 4.1, "Practical habits and systems for focused, sustainable work.", "notebook.jpg"),
    ("Yoga Mat", "Sports", 25.00, 85, "🧘", 4.4, "6 mm non-slip eco-friendly yoga mat with carry strap.", "yoga-mat.jpg"),
    ("Dumbbell Set", "Sports", 89.00, 18, "🏋️", 4.6, "Adjustable dumbbells, 2 to 20 kg per hand, quick-change dial.", "dumbbells.jpg"),
    ("Water Bottle", "Sports", 17.99, 130, "🥤", 4.3, "Insulated stainless-steel bottle, 750 ml, keeps drinks cold for 24 hours.", "water-bottle.jpg"),
]

# Used to burn the same CPU time when a login email does not exist (timing equalisation).
DUMMY_HASH = generate_password_hash("dummy-" + secrets.token_hex(8))


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def has_column(db, table, column):
    """Return True when a column exists.

    The table and column names are passed to SQLite as bound *values*, never
    concatenated into SQL, so they cannot alter the statement or its structure.
    """
    return db.execute(
        "SELECT 1 FROM pragma_table_info(?) WHERE name=? LIMIT 1",
        (table, column),
    ).fetchone() is not None


def init_db():
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if bool(admin_email) != bool(admin_password):
        raise RuntimeError("Set both ADMIN_EMAIL and ADMIN_PASSWORD to bootstrap an administrator.")
    if admin_email and ("@" not in admin_email or len(admin_password) < 12):
        raise RuntimeError("ADMIN_EMAIL must be valid and ADMIN_PASSWORD must be at least 12 characters.")

    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    # Migrations for databases created by older versions. Each statement is a
    # fixed string: no identifier, column definition or other SQL fragment is
    # ever built from a variable or user input.
    if not has_column(db, "products", "image"):
        db.execute("ALTER TABLE products ADD COLUMN image TEXT")
    if not has_column(db, "users", "auth_version"):
        db.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0")
    if not has_column(db, "users", "deleted_at"):
        db.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT")
    if not has_column(db, "orders", "idempotency_key"):
        db.execute("ALTER TABLE orders ADD COLUMN idempotency_key TEXT")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_idempotency ON orders(idempotency_key)")

    if db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO products(name,category,price,stock,emoji,rating,description,image) VALUES(?,?,?,?,?,?,?,?)", SEED)
    legacy_admin = db.execute(
        "SELECT id, password FROM users WHERE lower(email)=? AND is_admin=1",
        ("admin@shop.com",)).fetchone()
    if legacy_admin and check_password_hash(legacy_admin[1], "admin123"):
        if not admin_email:
            db.close()
            raise RuntimeError(
                "The database contains the default admin account. Set ADMIN_EMAIL and "
                "ADMIN_PASSWORD to replace its credentials before starting ShopEase.")
        db.execute(
            "UPDATE users SET email=?, password=?, auth_version=auth_version+1 WHERE id=?",
            (admin_email, generate_password_hash(admin_password), legacy_admin[0]))
    elif admin_email and db.execute(
            "SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] == 0:
        db.execute("INSERT INTO users(name,email,password,is_admin) VALUES(?,?,?,1)",
                   ("Store Admin", admin_email, generate_password_hash(admin_password)))
    for s in SEED:
        db.execute("UPDATE products SET image=? WHERE name=? AND (image IS NULL OR image='')",
                   (s[7], s[0]))
    db.commit()
    db.close()


# ---------- helpers ----------
def client_ip():
    return request.remote_addr or "unknown"


def audit(db, action, target="", detail="", actor_id=None):
    """Append to the audit log. Does NOT commit: the caller commits with its own work."""
    db.execute(
        "INSERT INTO audit_log(created_at, actor_id, action, target, ip, detail) VALUES(?,?,?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         actor_id if actor_id is not None else session.get("user_id"),
         action, str(target)[:200], client_ip(), str(detail)[:500]))


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        # A missing session token must fail (None == None used to pass), and compare in constant time.
        if not expected or not hmac.compare_digest(str(expected), str(supplied)):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.after_request
def security_headers(resp):
    csp = os.environ.get("CSP") or (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'")
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
    if SECURE_COOKIES:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.endpoint != "static" and session.get("user_id"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def rate_limit(scope, identity, limit, window_seconds=60):
    now = int(time.time())
    window_start = now - now % window_seconds
    identity_hash = hmac.new(
        app.config["SECRET_KEY"].encode(),
        f"{scope}:{identity}".encode(),
        hashlib.sha256,
    ).hexdigest()
    db = get_db()
    db.execute(
        """INSERT INTO request_limits(key, window_start, attempts) VALUES(?,?,1)
           ON CONFLICT(key) DO UPDATE SET
             window_start=excluded.window_start,
             attempts=CASE WHEN request_limits.window_start=excluded.window_start
                           THEN request_limits.attempts + 1 ELSE 1 END""",
        (identity_hash, window_start),
    )
    attempts = db.execute(
        "SELECT attempts FROM request_limits WHERE key=?", (identity_hash,)
    ).fetchone()["attempts"]
    db.execute("DELETE FROM request_limits WHERE window_start < ?", (now - 86400,))
    db.commit()
    return attempts <= limit


def current_user():
    """Return the signed-in user, or None.

    The session is only trusted if the user still exists, is not deleted and the
    session's auth version matches (bumped on logout / account deletion), so
    stolen or stale cookies are revoked server-side.
    """
    if "current_user" in g:
        return g.current_user
    user = None
    uid = session.get("user_id")
    if uid:
        row = get_db().execute(
            "SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
        if row and session.get("av") == row["auth_version"]:
            user = row
        else:
            session.clear()
    g.current_user = user
    return user


def start_session(user_id, auth_version, cart=None):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["av"] = auth_version
    if cart:
        session["cart"] = cart
    g.pop("current_user", None)


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not current_user():
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        user = current_user()
        if not user or not user["is_admin"]:
            abort(403)
        return view(*a, **kw)
    return wrapped


def D(x):
    return Decimal(str(x))


CENT = Decimal("0.01")


def cart_details():
    """Totals are computed with Decimal and rounded to cents (no float drift)."""
    cart = session.get("cart", {})
    items, subtotal = [], Decimal("0")
    if cart:
        ids = [int(i) for i in cart]
        rows = get_db().execute(
            f"SELECT * FROM products WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
        for p in rows:
            qty = min(cart[str(p["id"])], p["stock"], MAX_QTY)
            if qty < 1:
                continue
            line = (D(p["price"]) * qty).quantize(CENT, ROUND_HALF_UP)
            subtotal += line
            items.append({"product": p, "qty": qty, "line": float(line)})
    shipping = Decimal("0") if (subtotal >= D(FREE_SHIPPING_OVER) or not items) else D(SHIPPING_FEE)
    tax = (subtotal * D(TAX_RATE)).quantize(CENT, ROUND_HALF_UP)
    total = subtotal + shipping + tax
    return {"items": items, "subtotal": float(subtotal), "shipping": float(shipping),
            "tax": float(tax), "total": float(total)}


@app.context_processor
def inject_globals():
    return {
        "user": current_user(),
        "cart_count": sum(session.get("cart", {}).values()),
        "all_categories": [r[0] for r in get_db().execute(
            "SELECT DISTINCT category FROM products ORDER BY category")],
        "year": datetime.now().year,
    }


app.jinja_env.globals.update(csrf_token=csrf_token, STATUS_STEPS=STATUS_STEPS)


@app.template_filter("money")
def money(v):
    return f"${v:,.2f}"


def safe_next(url):
    """Only allow same-site relative paths (blocks //evil.com and /\\evil.com)."""
    default = url_for("index")
    if not url or "\\" in url or any(ord(c) < 32 for c in url):
        return default
    parts = urlparse(url)
    if parts.scheme or parts.netloc or not url.startswith("/") or url.startswith("//"):
        return default
    return url


def back(default_endpoint):
    """Redirect target taken from the Referer, but only if it is on this site."""
    ref = request.referrer
    if ref:
        p = urlparse(ref)
        if p.scheme in ("http", "https") and p.netloc == request.host:
            target = p.path + (("?" + p.query) if p.query else "")
            if target.startswith("/") and not target.startswith("//") and "\\" not in target:
                return target
    return url_for(default_endpoint)


def like_pattern(text):
    esc = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


def is_digits(s):
    return s.isascii() and s.isdigit()


def luhn_ok(number):
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def page_window(page, pages, radius=2):
    nums = sorted({1, pages} | {p for p in range(page - radius, page + radius + 1) if 1 <= p <= pages})
    out, last = [], 0
    for n in nums:
        if n - last > 1:
            out.append("…")
        out.append(n)
        last = n
    return out


# ---------- catalog ----------
@app.route("/")
def index():
    db = get_db()
    featured = db.execute("SELECT * FROM products ORDER BY rating DESC, id LIMIT 8").fetchall()
    cats = db.execute("SELECT category, COUNT(*) n, MIN(emoji) emoji FROM products GROUP BY category").fetchall()
    return render_template("index.html", featured=featured, cats=cats)


@app.route("/products")
def products():
    q = request.args.get("q", "").strip()[:LIMITS["q"]]
    cat = request.args.get("category", "")[:100]
    sort = request.args.get("sort", "featured")
    sort = sort if sort in SORTS else "featured"
    min_p = request.args.get("min_price", type=float)
    max_p = request.args.get("max_price", type=float)
    in_stock = request.args.get("in_stock") == "1"
    page = min(max(request.args.get("page", 1, type=int), 1), 100000)

    where, params = [], []
    if cat:
        where.append("category = ?")
        params.append(cat)
    if min_p is not None:
        where.append("price >= ?")
        params.append(min_p)
    if max_p is not None:
        where.append("price <= ?")
        params.append(max_p)
    if in_stock:
        where.append("stock > 0")
    if q:
        where.append("(name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
        params.extend([like_pattern(q), like_pattern(q)])
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_db()
    total = db.execute(
        f"SELECT COUNT(*) FROM (SELECT * FROM products {clause}\n)", params).fetchone()[0]
    pages = max((total + PER_PAGE - 1) // PER_PAGE, 1)
    page = min(page, pages)
    rows = db.execute(
        f"SELECT * FROM products {clause}\nORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()
    args = {k: v for k, v in request.args.items() if k != "page" and v}
    return render_template("products.html", products=rows, total=total, page=page,
                           pages=pages, page_window=page_window(page, pages), q=q, cat=cat,
                           sort=sort, min_p=min_p, max_p=max_p, in_stock=in_stock, args=args)


@app.route("/product/<int(max=2147483647):pid>")
def product(pid):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    related = db.execute("SELECT * FROM products WHERE category=? AND id!=? LIMIT 4",
                         (p["category"], pid)).fetchall()
    return render_template("product.html", p=p, related=related)


# ---------- cart ----------
@app.route("/cart")
def cart():
    return render_template("cart.html", c=cart_details(), free_over=FREE_SHIPPING_OVER)


@app.route("/cart/add/<int(max=2147483647):pid>", methods=["POST"])
def cart_add(pid):
    p = get_db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    qty = min(max(request.form.get("qty", 1, type=int), 1), MAX_QTY)
    cart_ = session.get("cart", {})
    new_qty = min(cart_.get(str(pid), 0) + qty, p["stock"], MAX_QTY)
    if new_qty < 1:
        flash(f"{p['name']} is out of stock.", "error")
    else:
        cart_[str(pid)] = new_qty
        session["cart"] = cart_
        flash(f"Added {p['name']} to your cart.", "success")
    return redirect(back("cart"))


@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart_ = session.get("cart", {})
    db = get_db()
    for key in list(cart_):
        qty = request.form.get(f"qty_{key}", type=int)
        if qty is None:
            continue
        p = db.execute("SELECT stock FROM products WHERE id=?", (int(key),)).fetchone()
        if qty < 1 or not p:
            cart_.pop(key)
        else:
            cart_[key] = min(qty, p["stock"], MAX_QTY)
    session["cart"] = cart_
    flash("Cart updated.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int(max=2147483647):pid>", methods=["POST"])
def cart_remove(pid):
    cart_ = session.get("cart", {})
    cart_.pop(str(pid), None)
    session["cart"] = cart_
    flash("Item removed.", "info")
    return redirect(url_for("cart"))


# ---------- checkout & orders ----------
def create_order_from_cart(user_id, form):
    """Returns (order_id, created). Idempotent per checkout via form['nonce']."""
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    key = form.get("nonce")
    if key:
        existing = db.execute(
            "SELECT id FROM orders WHERE idempotency_key=? AND user_id=?", (key, user_id)).fetchone()
        if existing:  # double-submit or replayed cookie: do not create a second order
            db.rollback()
            return existing["id"], False
    c = cart_details()
    if not c["items"]:
        db.rollback()
        flash("Your cart is empty or the items are no longer available.", "error")
        return None, False
    for it in c["items"]:  # final stock check
        fresh = db.execute("SELECT stock FROM products WHERE id=?",
                           (it["product"]["id"],)).fetchone()
        if not fresh or fresh["stock"] < it["qty"]:
            available = fresh["stock"] if fresh else 0
            db.rollback()
            flash(f"Only {available} of {it['product']['name']} left.", "error")
            return None, False
    cur = db.execute(
        "INSERT INTO orders(user_id,created_at,status,subtotal,shipping,tax,total,"
        "ship_name,ship_address,ship_city,ship_zip,ship_phone,payment,idempotency_key) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (user_id, datetime.now().strftime("%Y-%m-%d %H:%M"), "Placed",
         c["subtotal"], c["shipping"], c["tax"], c["total"], form["name"],
         form["address"], form["city"], form["zip"], form["phone"], form["payment"], key))
    oid = cur.lastrowid
    for it in c["items"]:
        p = it["product"]
        db.execute("INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)",
                   (oid, p["id"], p["name"], p["price"], it["qty"]))
        updated = db.execute(
            "UPDATE products SET stock = stock - ? WHERE id=? AND stock >= ?",
            (it["qty"], p["id"], it["qty"]),
        )
        if updated.rowcount != 1:
            db.rollback()
            flash(f"{p['name']} is no longer available in that quantity.", "error")
            return None, False
    db.commit()
    return oid, True


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    c = cart_details()
    if not c["items"]:
        flash("Your cart is empty.", "info")
        return redirect(url_for("products"))
    form = {k: request.form.get(k, "").strip() for k in
            ("name", "phone", "address", "city", "zip", "payment")}
    methods = ("Card (demo)", "Cash on Delivery") if DEMO_PAYMENTS else ("Cash on Delivery",)
    if request.method == "GET":
        form["name"] = current_user()["name"]
        form["payment"] = methods[0]
    else:
        errors = [f"{label} is required." for k, label in
                  (("name", "Full name"), ("phone", "Phone"), ("address", "Address"),
                   ("city", "City"), ("zip", "ZIP / postal code")) if not form[k]]
        errors += [f"{label} is too long." for k, label in
                   (("name", "Full name"), ("phone", "Phone"), ("address", "Address"),
                    ("city", "City"), ("zip", "ZIP / postal code")) if len(form[k]) > LIMITS[k]]
        if form["payment"] not in methods:
            errors.append("Choose a payment method.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            form["nonce"] = secrets.token_hex(16)  # idempotency key for this checkout
            session["pending_order"] = form
            return redirect(url_for("payment"))
    return render_template("checkout.html", c=c, form=form, demo_payments=DEMO_PAYMENTS)


@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    form = session.get("pending_order")
    c = cart_details()
    if not form:
        flash("No pending payment found.", "info")
        return redirect(url_for("checkout") if c["items"] else url_for("products"))
    if not c["items"]:
        session.pop("pending_order", None)
        flash("Your cart is empty.", "info")
        return redirect(url_for("cart"))
    is_card = form["payment"] == "Card (demo)"
    if is_card and not DEMO_PAYMENTS:
        abort(503, "Card payments are unavailable until a payment provider is configured.")
    if request.method == "POST":
        errors = []
        if is_card:
            # DEMO ONLY: in production use a provider's hosted fields (Stripe Elements, etc.)
            # so card data never reaches this server. Card data is validated and discarded,
            # never stored, logged or put in the session.
            card = {k: request.form.get(k, "").strip() for k in
                    ("card_name", "card_number", "card_expiry", "card_cvv")}
            number = card["card_number"].replace(" ", "")
            if not card["card_name"] or len(card["card_name"]) > LIMITS["card_name"]:
                errors.append("Name on card is required.")
            if not (is_digits(number) and len(number) == 16 and luhn_ok(number)):
                errors.append("Enter a valid 16-digit demo card number.")
            exp = card["card_expiry"]
            if not (len(exp) == 5 and exp[2] == "/" and is_digits(exp[:2])
                    and is_digits(exp[3:]) and 1 <= int(exp[:2]) <= 12):
                errors.append("Enter expiry as MM/YY.")
            else:
                mm, yy = int(exp[:2]), 2000 + int(exp[3:])
                now = datetime.now()
                if (yy, mm) < (now.year, now.month):
                    errors.append("Card expiry is in the past.")
            if not (is_digits(card["card_cvv"]) and 3 <= len(card["card_cvv"]) <= 4):
                errors.append("Enter a 3 or 4-digit CVV.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            oid, created = create_order_from_cart(session["user_id"], form)
            if oid is None:
                return redirect(url_for("cart"))
            session.pop("pending_order", None)
            session.pop("cart", None)
            if created:
                flash(f"Payment successful (demo). Order #{oid} placed. Thank you!", "success")
            else:
                flash(f"Order #{oid} was already placed.", "info")
            return redirect(url_for("order_detail", oid=oid))
    return render_template("payment.html", c=c, form=form, is_card=is_card)


def fetch_order(oid, owner_only=True):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        abort(404)
    user = current_user()
    if owner_only and o["user_id"] != session.get("user_id") and not (user and user["is_admin"]):
        abort(403)
    items = db.execute("SELECT * FROM order_items WHERE order_id=?", (oid,)).fetchall()
    return o, items


def cancel_open_order(db, oid):
    """Atomically cancel an order that is still Placed/Processing and restock it.

    Must run inside an open write transaction (BEGIN IMMEDIATE). The conditional
    UPDATE guarantees that only one caller can win, so stock is restored once.
    The caller commits.
    """
    cur = db.execute(
        "UPDATE orders SET status='Cancelled' WHERE id=? AND status IN ('Placed','Processing')",
        (oid,))
    if cur.rowcount != 1:
        return False
    for it in db.execute("SELECT product_id, qty FROM order_items WHERE order_id=?", (oid,)).fetchall():
        if it["product_id"] and it["qty"] > 0:
            db.execute("UPDATE products SET stock = stock + ? WHERE id=?",
                       (it["qty"], it["product_id"]))
    return True


@app.route("/orders")
@login_required
def orders():
    rows = get_db().execute(
        """SELECT o.*, (SELECT SUM(qty) FROM order_items WHERE order_id=o.id) AS n_items
           FROM orders o WHERE user_id=? ORDER BY o.id DESC""", (session["user_id"],)).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders/<int(max=2147483647):oid>")
@login_required
def order_detail(oid):
    o, items = fetch_order(oid)
    return render_template("order_detail.html", o=o, items=items)


@app.route("/orders/<int(max=2147483647):oid>/cancel", methods=["POST"])
@login_required
def order_cancel(oid):
    fetch_order(oid)  # ownership check (403 / 404)
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    if cancel_open_order(db, oid):
        audit(db, "order_cancelled", f"order:{oid}")
        db.commit()
        flash("Order cancelled.", "info")
    else:
        db.rollback()
        flash("This order can no longer be cancelled.", "error")
    return redirect(url_for("order_detail", oid=oid))


@app.route("/track", methods=["GET", "POST"])
@login_required
def track():
    order = items = None
    if request.method == "POST":
        if (not rate_limit("track-ip", client_ip(), 20)
                or not rate_limit("track-user", str(session["user_id"]), 30)):
            abort(429, "Too many tracking requests. Please try again in a minute.")
        oid = request.form.get("order_id", type=int) or 0
        if not 0 < oid <= 2147483647:
            oid = 0
        row = get_db().execute(
            "SELECT id FROM orders WHERE id=? AND user_id=?",
            (oid, session["user_id"]),
        ).fetchone()
        if row:
            order, items = fetch_order(row["id"])
        else:
            flash("No order matches that number in your account.", "error")
    return render_template("track.html", o=order, items=items)


# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not rate_limit("register-ip", client_ip(), 10, 3600):
            abort(429, "Too many sign-up attempts. Please try again later.")
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if (not name or len(name) > LIMITS["name"] or len(email) > LIMITS["email"]
                or not EMAIL_RE.match(email)
                or not MIN_PASSWORD <= len(pw) <= MAX_PASSWORD):
            flash(f"Enter your name, a valid email and a password of {MIN_PASSWORD}-{MAX_PASSWORD} characters.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                                 (name, email, generate_password_hash(pw)))
                audit(db, "register", f"user:{cur.lastrowid}", actor_id=cur.lastrowid)
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                # Generic message: does not confirm whether the email is registered.
                flash("We couldn't create that account. If you already have one, please sign in.", "error")
            else:
                start_session(cur.lastrowid, 0, session.get("cart"))
                flash("Welcome! Your account is ready.", "success")
                return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:LIMITS["email"]]
        password = request.form.get("password", "")
        ip = client_ip()
        # Per-IP limits slow guessing without allowing one source to lock out an account globally.
        if (not rate_limit("login-ip", ip, 30)
                or not rate_limit("login-account-ip", f"{ip}:{email}", 8)):
            abort(429, "Too many sign-in attempts. Please try again in a minute.")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=? AND deleted_at IS NULL", (email,)).fetchone()
        # Always run one hash check so response time does not reveal whether the email exists.
        valid = (len(password) <= MAX_PASSWORD
                 and check_password_hash(u["password"] if u else DUMMY_HASH, password))
        if u and valid:
            audit(db, "login_ok", f"user:{u['id']}", actor_id=u["id"])
            db.commit()
            start_session(u["id"], u["auth_version"], session.get("cart"))
            flash(f"Welcome back, {u['name']}.", "success")
            return redirect(safe_next(request.args.get("next")))
        audit(db, "login_failed", email, actor_id=0)
        db.commit()
        flash("Incorrect email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    uid = session.get("user_id")
    if uid:
        # Bumping auth_version revokes every session cookie issued for this account.
        db = get_db()
        db.execute("UPDATE users SET auth_version = auth_version + 1 WHERE id=?", (uid,))
        db.commit()
    session.clear()
    g.pop("current_user", None)
    flash("You are signed out.", "info")
    return redirect(url_for("index"))


# ---------- admin ----------
@app.route("/admin/orders")
@admin_required
def admin_orders():
    status = request.args.get("status", "")
    sql = "SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id"
    params = []
    if status in ALL_STATUSES:
        sql += " WHERE o.status=?"
        params.append(status)
    rows = get_db().execute(sql + " ORDER BY o.id DESC", params).fetchall()
    return render_template("admin_orders.html", orders=rows, statuses=ALL_STATUSES, sel=status)


@app.route("/admin/orders/<int(max=2147483647):oid>/status", methods=["POST"])
@admin_required
def admin_set_status(oid):
    status = request.form.get("status")
    if status not in ALL_STATUSES:
        abort(400)
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    o = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        db.rollback()
        abort(404)
    if o["status"] in TERMINAL_STATUSES:
        db.rollback()
        flash(f"Order #{oid} is {o['status']} and can no longer be changed.", "error")
        return redirect(back("admin_orders"))
    if status == "Cancelled":
        # Goes through the same atomic path as customer cancellation so stock is restored once.
        if not cancel_open_order(db, oid):
            db.rollback()
            flash("Only Placed or Processing orders can be cancelled.", "error")
            return redirect(back("admin_orders"))
    else:
        tracking = o["tracking"]
        if status in ("Shipped", "Out for Delivery", "Delivered") and not tracking:
            tracking = "TRK" + secrets.token_hex(5).upper()
        db.execute("UPDATE orders SET status=?, tracking=? WHERE id=?", (status, tracking, oid))
    audit(db, "order_status", f"order:{oid}", f"{o['status']} -> {status}")
    db.commit()
    flash(f"Order #{oid} set to {status}.", "success")
    return redirect(back("admin_orders"))


@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q", "").strip()[:LIMITS["q"]]
    where, params = ["u.deleted_at IS NULL"], []
    if q:
        where.append("(u.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\')")
        params = [like_pattern(q)] * 2
    rows = get_db().execute(
        f"""SELECT u.id, u.name, u.email, u.is_admin,
                   COUNT(o.id) AS orders,
                   COALESCE(SUM(CASE WHEN o.status != 'Cancelled' THEN o.total END), 0) AS spent,
                   MAX(o.created_at) AS last_order
            FROM users u LEFT JOIN orders o ON o.user_id = u.id
            WHERE {' AND '.join(where)} GROUP BY u.id ORDER BY u.is_admin DESC, u.id""", params).fetchall()
    return render_template("admin_users.html", users=rows, q=q)


@app.route("/admin/users/<int(max=2147483647):uid>")
@admin_required
def admin_user_detail(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    orders = db.execute(
        """SELECT o.*, (SELECT COALESCE(SUM(qty),0) FROM order_items WHERE order_id=o.id) AS n_items
           FROM orders o WHERE user_id=? ORDER BY o.id DESC""", (uid,)).fetchall()
    items = {o["id"]: db.execute(
        "SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall() for o in orders}
    stats = db.execute(
        """SELECT COUNT(*) AS orders,
                  COALESCE(SUM(CASE WHEN status != 'Cancelled' THEN total END), 0) AS spent
           FROM orders WHERE user_id=?""", (uid,)).fetchone()
    return render_template("admin_user_detail.html", u=u, orders=orders, items=items, stats=stats)


@app.route("/admin/users/<int(max=2147483647):uid>/delete", methods=["POST"])
@admin_required
def admin_user_delete(uid):
    """Deactivate and anonymise a customer.

    Order and payment history is kept (financial record keeping). Only orders that
    are still open are cancelled and restocked; shipped or delivered goods are not
    put back into inventory. Administrator accounts cannot be deleted here, which
    also guarantees the last admin can never be removed.
    """
    if uid == session.get("user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_users"))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    u = db.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (uid,)).fetchone()
    if not u:
        db.rollback()
        abort(404)
    if u["is_admin"]:
        db.rollback()
        flash("Administrator accounts cannot be deleted from the web interface.", "error")
        return redirect(url_for("admin_users"))
    cancelled = 0
    for o in db.execute("SELECT id FROM orders WHERE user_id=?", (uid,)).fetchall():
        if cancel_open_order(db, o["id"]):
            cancelled += 1
    db.execute(
        "UPDATE users SET name='Deleted user', email=?, password=?, deleted_at=?, "
        "auth_version=auth_version+1 WHERE id=?",
        (f"deleted-{uid}@deleted.invalid", generate_password_hash(secrets.token_hex(32)),
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"), uid))
    audit(db, "user_deleted", f"user:{uid}", f"open orders cancelled: {cancelled}")
    db.commit()
    flash(f"Deleted user {u['name']} ({u['email']}). Order history was retained.", "success")
    return redirect(url_for("admin_users"))


def error_page(e):
    return render_template("error.html", e=e), e.code


for _code in (400, 403, 404, 405, 413, 429, 503):
    app.errorhandler(_code)(error_page)


init_db()

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False)