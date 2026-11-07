# ShopEase – Flask e-commerce app

## Run
    python -m venv venv
    source venv/bin/activate        # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    # macOS/Linux:
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export ADMIN_EMAIL="admin@example.com"
    export ADMIN_PASSWORD="replace-with-a-long-unique-password"
    # Windows PowerShell:
    # $env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
    # $env:ADMIN_EMAIL = "admin@example.com"
    # $env:ADMIN_PASSWORD = "replace-with-a-long-unique-password"
    python app.py                   # http://127.0.0.1:5000

The SQLite DB (`instance/shop.db`) and 24 sample products are created on first run.
`SECRET_KEY` is required and must be at least 32 characters; use a randomly generated value.
`ADMIN_EMAIL` and `ADMIN_PASSWORD` must both be set to create an administrator on a fresh
database; the password must be at least 12 characters. A database that still has the old
default `admin@shop.com` administrator is refused at startup; set both admin variables to
replace its credentials before starting the app.

## Admin
Sign in with the administrator credentials configured through the environment to update order
statuses. Keep these values private and use a unique password.

## Features
Home, catalog, search, category/price/stock filters, sort, pagination, product page,
session cart, checkout (login required), order history, order timeline tracking,
guest-style tracking by order number + email, order cancellation (restores stock),
admin status management, CSRF protection, responsive layout.
