import os
import json
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    render_template_string,
    redirect,
    url_for,
    session,
    flash,
)


# ============================================================
# CONFIGURATION
# ============================================================

APP = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "api_manager.db")

ADMIN_TOKEN = os.environ.get(
    "ADMIN_TOKEN",
    "bismaya"
)

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    "my-m-12345"
)

PUBLIC_BASE_URL = os.environ.get(
    "PUBLIC_BASE_URL",
    ""
).rstrip("/")

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))

APP.secret_key = SESSION_SECRET


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            response_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT,
            request_limit INTEGER NOT NULL DEFAULT 0,
            total_requests INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT,
            request_limit INTEGER NOT NULL DEFAULT 0,
            total_requests INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(api_id) REFERENCES apis(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_id INTEGER NOT NULL,
            key_id INTEGER NOT NULL,
            ip TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(api_id) REFERENCES apis(id),
            FOREIGN KEY(key_id) REFERENCES api_keys(id)
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


def utc_now_string():
    return utc_now().isoformat()


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def is_expired(value):
    if not value:
        return False

    date_value = parse_datetime(value)

    if date_value is None:
        return True

    return utc_now() >= date_value


def create_hash(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def generate_api_key():
    return (
        "sk_live_"
        + secrets.token_urlsafe(32)
    )


def clean_path(value):
    value = (value or "").strip()

    value = value.strip("/")

    while "//" in value:
        value = value.replace("//", "/")

    return value


def get_base_url():
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL

    return f"http://127.0.0.1:{PORT}"


def get_api_url(path):
    return (
        get_base_url()
        + "/api/"
        + path.strip("/")
    )


def authentication_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get(
            "admin_logged_in",
            False
        ):
            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


def find_api(path):
    connection = get_db()

    result = connection.execute(
        """
        SELECT *
        FROM apis
        WHERE path = ?
        LIMIT 1
        """,
        (path,)
    ).fetchone()

    connection.close()

    return result


# ============================================================
# LOGIN PAGE
# ============================================================

LOGIN_HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>API Manager Login</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;

    display: flex;
    align-items: center;
    justify-content: center;

    font-family: Arial, sans-serif;

    background:
        radial-gradient(
            circle at top,
            #18243a,
            #070b12 60%
        );

    color: white;
}

.login-box {
    width: min(420px, 92%);

    padding: 28px;

    background: #111827;

    border: 1px solid #293548;

    border-radius: 18px;

    box-shadow:
        0 25px 70px rgba(0,0,0,.45);
}

h1 {
    margin-top: 0;
}

label {
    display: block;

    color: #cbd5e1;

    margin-bottom: 8px;
}

input {
    width: 100%;

    padding: 13px;

    margin-bottom: 16px;

    border-radius: 10px;

    border: 1px solid #334155;

    background: #070b12;

    color: white;

    outline: none;
}

input:focus {
    border-color: #00e676;
}

button {
    border: 0;

    border-radius: 10px;

    padding: 12px 18px;

    background: #00c853;

    color: white;

    font-weight: bold;

    cursor: pointer;
}

.message {
    background: #172033;

    border: 1px solid #334155;

    padding: 12px;

    border-radius: 10px;

    margin-bottom: 15px;
}

</style>

</head>

<body>

<div class="login-box">

<h1>🔐 API Manager</h1>

<p>
Administrator login
</p>

{% with messages = get_flashed_messages() %}

{% for message in messages %}

<div class="message">
{{ message }}
</div>

{% endfor %}

{% endwith %}

<form method="POST">

<label>
Admin Token
</label>

<input
type="password"
name="token"
placeholder="Enter admin token"
required
>

<button type="submit">
Login
</button>

</form>

</div>

</body>

</html>
"""


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>API Manager</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    font-family: Arial, sans-serif;

    color: #f8fafc;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at top,
            #18243a,
            #070b12 55%
        );
}

.container {
    width: min(1150px, 94%);

    margin: auto;

    padding:
        25px
        0
        120px;
}

.header {
    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 15px;

    margin-bottom: 22px;
}

.logo {
    font-size: 27px;

    font-weight: 800;
}

.logo span {
    color: #00e676;
}

.card {
    background: #111827ee;

    border:
        1px solid
        #293548;

    border-radius: 18px;

    padding: 20px;

    margin-bottom: 20px;

    box-shadow:
        0 15px 40px rgba(0,0,0,.25);
}

.grid {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(230px,1fr)
        );

    gap: 14px;
}

.stat {
    background: #0b111c;

    border:
        1px solid
        #263346;

    border-radius: 14px;

    padding: 18px;
}

.number {
    font-size: 29px;

    font-weight: 800;

    margin-top: 5px;
}

label {
    display: block;

    color: #cbd5e1;

    margin-bottom: 15px;
}

input,
textarea,
select {
    width: 100%;

    padding: 12px;

    margin-top: 7px;

    background: #080d15;

    border:
        1px solid
        #334155;

    border-radius: 10px;

    color: white;

    outline: none;
}

textarea {
    min-height: 130px;

    resize: vertical;
}

input:focus,
textarea:focus,
select:focus {
    border-color: #00e676;
}

button,
.btn {
    display: inline-block;

    border: 0;

    border-radius: 10px;

    padding: 11px 15px;

    font-weight: bold;

    cursor: pointer;

    text-decoration: none;

    background: #00c853;

    color: white;
}

.blue {
    background: #2563eb;
}

.red {
    background: #d50000;
}

.orange {
    background: #f59e0b;
}

.gray {
    background: #374151;
}

.actions {
    display: flex;

    flex-wrap: wrap;

    gap: 8px;

    margin-top: 14px;
}

.inline {
    display: inline;
}

.status {
    display: inline-block;

    padding: 5px 9px;

    border-radius: 999px;

    font-size: 11px;

    font-weight: bold;
}

.active {
    color: #00e676;

    border:
        1px solid
        #00e676;

    background: #00e67618;
}

.inactive {
    color: #ff1744;

    border:
        1px solid
        #ff1744;

    background: #ff174418;
}

.small {
    font-size: 13px;

    color: #94a3b8;
}

.api {
    background: #080d15;

    border:
        1px solid
        #293548;

    border-radius: 14px;

    padding: 15px;

    margin-top: 15px;
}

.copy-row {
    display: flex;

    gap: 8px;

    align-items: center;
}

.copy-row input {
    margin: 0;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;

    border-collapse: collapse;
}

th,
td {
    padding: 11px 7px;

    border-bottom:
        1px solid
        #293548;

    text-align: left;

    vertical-align: top;
}

th {
    color: #94a3b8;
}

.flash {
    background: #172033;

    border:
        1px solid
        #334155;

    border-radius: 10px;

    padding: 12px;

    margin-bottom: 15px;
}

.bottom-url {
    position: fixed;

    left: 0;
    right: 0;
    bottom: 0;

    background: #05080df5;

    border-top:
        1px solid
        #293548;

    padding: 12px;
}

.bottom-inner {
    width: min(1150px, 94%);

    margin: auto;
}

@media(max-width:600px) {

    .header {
        align-items: flex-start;
    }

    .copy-row {
        flex-direction: column;

        align-items: stretch;
    }

    .copy-row button {
        width: 100%;
    }

}

</style>

<script>

function copyValue(id) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    const value =
        element.value ||
        element.innerText;

    if (
        navigator.clipboard &&
        window.isSecureContext
    ) {

        navigator.clipboard
            .writeText(value)
            .then(function() {
                alert("Copied!");
            })
            .catch(function() {
                fallbackCopy(element);
            });

    } else {

        fallbackCopy(element);

    }
}


function fallbackCopy(element) {

    element.focus();

    element.select();

    element.setSelectionRange(
        0,
        element.value.length
    );

    document.execCommand("copy");

    alert("Copied!");

}

</script>

</head>

<body>

<div class="container">


<div class="header">

<div class="logo">
API <span>MANAGER</span>
</div>

<a
class="btn red"
href="{{ url_for('logout') }}"
>
Logout
</a>

</div>


{% with messages =
get_flashed_messages() %}

{% for message in messages %}

<div class="flash">
{{ message }}
</div>

{% endfor %}

{% endwith %}


<!-- STATISTICS -->

<div class="grid">

<div class="stat">

<div class="small">
Total APIs
</div>

<div class="number">
{{ stats.apis }}
</div>

</div>


<div class="stat">

<div class="small">
Active APIs
</div>

<div class="number">
{{ stats.active_apis }}
</div>

</div>


<div class="stat">

<div class="small">
Total API Keys
</div>

<div class="number">
{{ stats.keys }}
</div>

</div>


<div class="stat">

<div class="small">
Total Requests
</div>

<div class="number">
{{ stats.requests }}
</div>

</div>

</div>


<!-- CREATE API -->

<div class="card">

<h2>
➕ Create New API
</h2>

<form
method="POST"
action="{{ url_for('create_api') }}"
>

<div class="grid">


<label>

API Name

<input
type="text"
name="name"
placeholder="My API"
required
>

</label>


<label>

API Path

<input
type="text"
name="path"
placeholder="my-api"
required
>

<div class="small">
Example:
my-api creates /api/my-api
</div>

</label>


<label>

API Expiration

<select name="expires_days">

<option value="0">
Never
</option>

<option value="1">
1 Day
</option>

<option value="7">
7 Days
</option>

<option value="30">
30 Days
</option>

<option value="90">
90 Days
</option>

<option value="365">
365 Days
</option>

</select>

</label>


<label>

API Request Limit

<input
type="number"
name="request_limit"
value="0"
min="0"
>

<div class="small">
0 = unlimited
</div>

</label>


</div>


<label>

Custom JSON Response

<textarea
name="response_json"
>{
  "success": true,
  "message": "API is working"
}</textarea>

</label>


<button type="submit">
Create API
</button>

</form>

</div>


<!-- API LIST -->

<div class="card">

<h2>
📡 Your APIs
</h2>


{% if apis %}


{% for api in apis %}


<div class="api">


<div class="header">

<div>

<h2>
{{ api["name"] }}
</h2>


{% if
api["enabled"]
and not expired(api["expires_at"])
%}

<span class="status active">
ACTIVE
</span>

{% else %}

<span class="status inactive">
INACTIVE
</span>

{% endif %}

</div>


<div class="small">
ID: {{ api["id"] }}
</div>

</div>


<p class="small">

API Path:

<strong>
/api/{{ api["path"] }}
</strong>

</p>


<div class="copy-row">

<input
id="api-url-{{ api['id'] }}"
readonly
value="{{ make_api_url(api['path']) }}"
>

<button
type="button"
class="blue"
onclick="
copyValue(
'api-url-{{ api['id'] }}'
)
"
>
📋 Copy API URL
</button>

</div>


<p class="small">

Requests:

{{ api["total_requests"] }}

{% if api["request_limit"] > 0 %}

/
{{ api["request_limit"] }}

{% else %}

/
Unlimited

{% endif %}

</p>


<p class="small">

Expires:

{% if api["expires_at"] %}

{{ api["expires_at"] }}

{% else %}

Never

{% endif %}

</p>


<div class="actions">


<form
class="inline"
method="POST"
action="{{
url_for(
'toggle_api',
api_id=api['id']
)
}}"
>

<button
type="submit"
class="orange"
>

{% if api["enabled"] %}
Disable
{% else %}
Enable
{% endif %}

</button>

</form>


<form
class="inline"
method="POST"
action="{{
url_for(
'delete_api',
api_id=api['id']
)
}}"
onsubmit="
return confirm(
'Delete this API and all its keys?'
)
"
>

<button
type="submit"
class="red"
>
Delete API
</button>

</form>


</div>


<!-- CREATE KEY -->

<h3>
🔑 Generate API Key
</h3>


<form
method="POST"
action="{{
url_for(
'create_key',
api_id=api['id']
)
}}"
>


<div class="grid">


<label>

Key Name

<input
type="text"
name="name"
placeholder="My Key"
required
>

</label>


<label>

Key Expiration

<select name="expires_days">

<option value="0">
Never
</option>

<option value="1">
1 Day
</option>

<option value="7">
7 Days
</option>

<option value="30">
30 Days
</option>

<option value="90">
90 Days
</option>

<option value="365">
365 Days
</option>

</select>

</label>


<label>

Key Request Limit

<input
type="number"
name="request_limit"
value="0"
min="0"
>

<div class="small">
0 = unlimited
</div>

</label>


</div>


<button type="submit">
Generate API Key
</button>

</form>


<!-- KEY LIST -->

{% set api_keys =
keys_by_api.get(
api["id"],
[]
)
%}


{% if api_keys %}


<div class="table-wrap">

<table>

<thead>

<tr>

<th>
Name
</th>

<th>
Key
</th>

<th>
Status
</th>

<th>
Requests
</th>

<th>
Actions
</th>

</tr>

</thead>


<tbody>


{% for key in api_keys %}


<tr>


<td>
{{ key["name"] }}
</td>


<td>
<span class="small">
{{ key["key_prefix"] }}...
</span>
</td>


<td>


{% if
key["enabled"]
and not expired(key["expires_at"])
%}

<span class="status active">
ACTIVE
</span>

{% else %}

<span class="status inactive">
INACTIVE
</span>

{% endif %}


</td>


<td>

{{ key["total_requests"] }}

{% if key["request_limit"] > 0 %}

/
{{ key["request_limit"] }}

{% else %}

/
Unlimited

{% endif %}

</td>


<td>


<form
class="inline"
method="POST"
action="{{
url_for(
'toggle_key',
key_id=key['id']
)
}}"
>

<button
type="submit"
class="gray"
>

{% if key["enabled"] %}
Revoke
{% else %}
Enable
{% endif %}

</button>

</form>


<form
class="inline"
method="POST"
action="{{
url_for(
'delete_key',
key_id=key['id']
)
}}"
onsubmit="
return confirm(
'Delete this API key?'
)
"
>

<button
type="submit"
class="red"
>
Delete
</button>

</form>


</td>


</tr>


{% endfor %}


</tbody>

</table>

</div>


{% else %}


<p class="small">
No API keys created yet.
</p>


{% endif %}


</div>


{% endfor %}


{% else %}


<p class="small">
No APIs created yet.
</p>


{% endif %}


</div>


<!-- USAGE -->

<div class="card">

<h2>
📖 API Usage
</h2>


<p>
Send the API key using the
Authorization header:
</p>


<div class="api">

Authorization: Bearer YOUR_API_KEY

</div>


<p>
Example:
</p>


<div class="api">

curl -H "Authorization: Bearer YOUR_API_KEY" "{{ base }}/api/example"

</div>


</div>


</div>


<!-- API URL AT BOTTOM -->

<div class="bottom-url">

<div class="bottom-inner">

<div class="small">
API BASE URL
</div>


<div class="copy-row">

<input
id="base-url"
readonly
value="{{ base }}"
>


<button
type="button"
onclick="
copyValue('base-url')
"
>
📋 Copy API URL
</button>


</div>

</div>

</div>


</body>

</html>
"""


# ============================================================
# API KEY CREATED PAGE
# ============================================================

KEY_CREATED_HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>API Key Created</title>

<style>

body {
    margin: 0;

    padding: 25px;

    background: #070b12;

    color: white;

    font-family: Arial, sans-serif;
}

.box {
    width: min(700px, 94%);

    margin: 70px auto;

    background: #111827;

    border:
        1px solid
        #293548;

    border-radius: 18px;

    padding: 25px;
}

input {
    width: 100%;

    box-sizing: border-box;

    padding: 14px;

    background: #070b12;

    color: white;

    border:
        1px solid
        #334155;

    border-radius: 10px;

    margin: 10px 0;
}

button,
a {
    display: inline-block;

    padding: 12px 17px;

    border: 0;

    border-radius: 10px;

    background: #00c853;

    color: white;

    font-weight: bold;

    text-decoration: none;

    cursor: pointer;
}

.warning {
    color: #ffca28;
}

</style>

<script>

function copyKey() {

    const input =
        document.getElementById("new-key");

    input.focus();

    input.select();

    input.setSelectionRange(
        0,
        input.value.length
    );

    if (navigator.clipboard) {

        navigator.clipboard
            .writeText(input.value)
            .then(function() {
                alert("API key copied!");
            })
            .catch(function() {
                document.execCommand("copy");
                alert("API key copied!");
            });

    } else {

        document.execCommand("copy");

        alert("API key copied!");

    }

}

</script>

</head>

<body>

<div class="box">

<h1>
✅ API Key Created
</h1>

<p>
Your new API key:
</p>


<input
id="new-key"
readonly
value="{{ key }}"
>


<button
onclick="copyKey()"
>
📋 Copy API Key
</button>


<p class="warning">

⚠️ Save this key now.

The complete key is displayed only once.

</p>


<br><br>


<a
href="{{ url_for('dashboard') }}"
>
← Back to Dashboard
</a>


</div>

</body>

</html>
"""


# ============================================================
# LOGIN
# ============================================================

@APP.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        token = request.form.get(
            "token",
            ""
        ).strip()

        if secrets.compare_digest(
            token,
            ADMIN_TOKEN
        ):

            session["admin_logged_in"] = True

            return redirect(
                url_for("dashboard")
            )

        flash("Invalid admin token.")

    return render_template_string(
        LOGIN_HTML
    )


# ============================================================
# LOGOUT
# ============================================================

@APP.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HOME
# ============================================================

@APP.route("/")
def home():

    if session.get(
        "admin_logged_in",
        False
    ):

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@APP.route("/dashboard")
@authentication_required
def dashboard():

    connection = get_db()

    apis = connection.execute(
        """
        SELECT *
        FROM apis
        ORDER BY id DESC
        """
    ).fetchall()

    keys = connection.execute(
        """
        SELECT *
        FROM api_keys
        ORDER BY id DESC
        """
    ).fetchall()

    request_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM usage
        """
    ).fetchone()[0]

    connection.close()


    keys_by_api = {}

    for key in keys:

        api_id = key["api_id"]

        if api_id not in keys_by_api:

            keys_by_api[api_id] = []

        keys_by_api[api_id].append(key)


    statistics = {

        "apis": len(apis),

        "active_apis": sum(
            1
            for api in apis
            if api["enabled"]
            and not is_expired(
                api["expires_at"]
            )
        ),

        "keys": len(keys),

        "requests": request_count

    }


    return render_template_string(

        DASHBOARD_HTML,

        apis=apis,

        keys_by_api=keys_by_api,

        stats=statistics,

        expired=is_expired,

        make_api_url=get_api_url,

        base=get_base_url()

    )


# ============================================================
# CREATE API
# ============================================================

@APP.route(
    "/admin/api/create",
    methods=["POST"]
)
@authentication_required
def create_api():

    name = request.form.get(
        "name",
        ""
    ).strip()

    path = clean_path(
        request.form.get(
            "path",
            ""
        )
    )

    response_text = request.form.get(
        "response_json",
        ""
    ).strip()


    try:

        expires_days = int(
            request.form.get(
                "expires_days",
                "0"
            )
        )

        request_limit = int(
            request.form.get(
                "request_limit",
                "0"
            )
        )

        if (
            expires_days < 0
            or request_limit < 0
        ):
            raise ValueError

    except ValueError:

        flash(
            "Invalid expiration or request limit."
        )

        return redirect(
            url_for("dashboard")
        )


    if not name or not path:

        flash(
            "API name and path are required."
        )

        return redirect(
            url_for("dashboard")
        )


    if path == "health":

        flash(
            "The health path is reserved."
        )

        return redirect(
            url_for("dashboard")
        )


    try:

        parsed_json = json.loads(
            response_text
        )

        response_text = json.dumps(
            parsed_json,
            ensure_ascii=False
        )

    except Exception:

        flash(
            "Invalid JSON response."
        )

        return redirect(
            url_for("dashboard")
        )


    expires_at = None

    if expires_days > 0:

        expires_at = (
            utc_now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()


    connection = get_db()

    try:

        connection.execute(
            """
            INSERT INTO apis
            (
                name,
                path,
                response_json,
                enabled,
                expires_at,
                request_limit,
                total_requests,
                created_at
            )
            VALUES
            (?, ?, ?, 1, ?, ?, 0, ?)
            """,
            (
                name,
                path,
                response_text,
                expires_at,
                request_limit,
                utc_now_string()
            )
        )

        connection.commit()

        flash(
            "API created successfully."
        )

    except sqlite3.IntegrityError:

        flash(
            "That API path already exists."
        )

    finally:

        connection.close()


    return redirect(
        url_for("dashboard")
    )


# ============================================================
# ENABLE / DISABLE API
# ============================================================

@APP.route(
    "/admin/api/<int:api_id>/toggle",
    methods=["POST"]
)
@authentication_required
def toggle_api(api_id):

    connection = get_db()

    api = connection.execute(
        """
        SELECT enabled
        FROM apis
        WHERE id = ?
        """,
        (api_id,)
    ).fetchone()


    if not api:

        connection.close()

        flash("API not found.")

        return redirect(
            url_for("dashboard")
        )


    new_value = (
        0
        if api["enabled"]
        else 1
    )


    connection.execute(
        """
        UPDATE apis
        SET enabled = ?
        WHERE id = ?
        """,
        (
            new_value,
            api_id
        )
    )

    connection.commit()

    connection.close()


    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DELETE API
# ============================================================

@APP.route(
    "/admin/api/<int:api_id>/delete",
    methods=["POST"]
)
@authentication_required
def delete_api(api_id):

    connection = get_db()


    connection.execute(
        """
        DELETE FROM usage
        WHERE api_id = ?
        """,
        (api_id,)
    )


    connection.execute(
        """
        DELETE FROM api_keys
        WHERE api_id = ?
        """,
        (api_id,)
    )


    connection.execute(
        """
        DELETE FROM apis
        WHERE id = ?
        """,
        (api_id,)
    )


    connection.commit()

    connection.close()


    flash("API deleted.")

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# CREATE API KEY
# ============================================================

@APP.route(
    "/admin/api/<int:api_id>/key/create",
    methods=["POST"]
)
@authentication_required
def create_key(api_id):

    name = request.form.get(
        "name",
        ""
    ).strip()


    if not name:
        name = "API Key"


    try:

        expires_days = int(
            request.form.get(
                "expires_days",
                "0"
            )
        )

        request_limit = int(
            request.form.get(
                "request_limit",
                "0"
            )
        )

        if (
            expires_days < 0
            or request_limit < 0
        ):
            raise ValueError

    except ValueError:

        flash(
            "Invalid key settings."
        )

        return redirect(
            url_for("dashboard")
        )


    connection = get_db()


    api = connection.execute(
        """
        SELECT id
        FROM apis
        WHERE id = ?
        """,
        (api_id,)
    ).fetchone()


    if not api:

        connection.close()

        flash(
            "API not found."
        )

        return redirect(
            url_for("dashboard")
        )


    raw_key = generate_api_key()

    key_hash = create_hash(
        raw_key
    )

    key_prefix = raw_key[:20]


    expires_at = None

    if expires_days > 0:

        expires_at = (
            utc_now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()


    connection.execute(
        """
        INSERT INTO api_keys
        (
            api_id,
            name,
            key_hash,
            key_prefix,
            enabled,
            expires_at,
            request_limit,
            total_requests,
            created_at
        )
        VALUES
        (?, ?, ?, ?, 1, ?, ?, 0, ?)
        """,
        (
            api_id,
            name,
            key_hash,
            key_prefix,
            expires_at,
            request_limit,
            utc_now_string()
        )
    )


    connection.commit()

    connection.close()


    return render_template_string(
        KEY_CREATED_HTML,
        key=raw_key
    )


# ============================================================
# ENABLE / REVOKE KEY
# ============================================================

@APP.route(
    "/admin/key/<int:key_id>/toggle",
    methods=["POST"]
)
@authentication_required
def toggle_key(key_id):

    connection = get_db()


    key = connection.execute(
        """
        SELECT enabled
        FROM api_keys
        WHERE id = ?
        """,
        (key_id,)
    ).fetchone()


    if not key:

        connection.close()

        flash(
            "API key not found."
        )

        return redirect(
            url_for("dashboard")
        )


    new_value = (
        0
        if key["enabled"]
        else 1
    )


    connection.execute(
        """
        UPDATE api_keys
        SET enabled = ?
        WHERE id = ?
        """,
        (
            new_value,
            key_id
        )
    )


    connection.commit()

    connection.close()


    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DELETE KEY
# ============================================================

@APP.route(
    "/admin/key/<int:key_id>/delete",
    methods=["POST"]
)
@authentication_required
def delete_key(key_id):

    connection = get_db()


    connection.execute(
        """
        DELETE FROM usage
        WHERE key_id = ?
        """,
        (key_id,)
    )


    connection.execute(
        """
        DELETE FROM api_keys
        WHERE id = ?
        """,
        (key_id,)
    )


    connection.commit()

    connection.close()


    flash(
        "API key deleted."
    )


    return redirect(
        url_for("dashboard")
    )


# ============================================================
# PUBLIC API
# ============================================================

@APP.route(
    "/api/<path:api_path>",
    methods=["GET", "POST"]
)
def public_api(api_path):

    path = clean_path(
        api_path
    )


    api = find_api(path)


    if not api:

        return jsonify({
            "success": False,
            "error": "API not found"
        }), 404


    # --------------------------------------------------------
    # API STATUS
    # --------------------------------------------------------

    if not api["enabled"]:

        return jsonify({
            "success": False,
            "error": "API disabled"
        }), 403


    if is_expired(
        api["expires_at"]
    ):

        return jsonify({
            "success": False,
            "error": "API expired"
        }), 403


    # --------------------------------------------------------
    # API REQUEST LIMIT
    # --------------------------------------------------------

    if (
        api["request_limit"] > 0
        and api["total_requests"]
        >= api["request_limit"]
    ):

        return jsonify({
            "success": False,
            "error": "API request limit reached"
        }), 429


    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------

    authorization = request.headers.get(
        "Authorization",
        ""
    ).strip()


    if not authorization.startswith(
        "Bearer "
    ):

        return jsonify({
            "success": False,
            "error": "Authorization header required"
        }), 401


    raw_key = authorization[
        7:
    ].strip()


    if not raw_key:

        return jsonify({
            "success": False,
            "error": "API key required"
        }), 401


    key_hash = create_hash(
        raw_key
    )


    connection = get_db()


    key = connection.execute(
        """
        SELECT *
        FROM api_keys
        WHERE api_id = ?
        AND key_hash = ?
        LIMIT 1
        """,
        (
            api["id"],
            key_hash
        )
    ).fetchone()


    if not key:

        connection.close()

        return jsonify({
            "success": False,
            "error": "Invalid API key"
        }), 401


    # --------------------------------------------------------
    # KEY STATUS
    # --------------------------------------------------------

    if not key["enabled"]:

        connection.close()

        return jsonify({
            "success": False,
            "error": "API key revoked"
        }), 403


    if is_expired(
        key["expires_at"]
    ):

        connection.close()

        return jsonify({
            "success": False,
            "error": "API key expired"
        }), 403


    # --------------------------------------------------------
    # KEY REQUEST LIMIT
    # --------------------------------------------------------

    if (
        key["request_limit"] > 0
        and key["total_requests"]
        >= key["request_limit"]
    ):

        connection.close()

        return jsonify({
            "success": False,
            "error": "API key request limit reached"
        }), 429


    # --------------------------------------------------------
    # REQUEST INFORMATION
    # --------------------------------------------------------

    ip_address = (
        request.headers.get(
            "CF-Connecting-IP"
        )
        or request.remote_addr
        or ""
    )


    user_agent = request.headers.get(
        "User-Agent",
        ""
    )


    # --------------------------------------------------------
    # UPDATE COUNTERS
    # --------------------------------------------------------

    connection.execute(
        """
        UPDATE apis
        SET total_requests =
            total_requests + 1
        WHERE id = ?
        """,
        (
            api["id"],
        )
    )


    connection.execute(
        """
        UPDATE api_keys
        SET total_requests =
            total_requests + 1
        WHERE id = ?
        """,
        (
            key["id"],
        )
    )


    connection.execute(
        """
        INSERT INTO usage
        (
            api_id,
            key_id,
            ip,
            user_agent,
            created_at
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            api["id"],
            key["id"],
            ip_address,
            user_agent,
            utc_now_string()
        )
    )


    connection.commit()

    connection.close()


    # --------------------------------------------------------
    # RETURN CUSTOM JSON
    # --------------------------------------------------------

    try:

        result = json.loads(
            api["response_json"]
        )

    except Exception:

        result = {
            "success": True,
            "message": "API is working"
        }


    return jsonify(result)


# ============================================================
# HEALTH CHECK
# ============================================================

@APP.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "api-manager",
        "time": utc_now_string()
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@APP.errorhandler(404)
def page_not_found(error):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify({
            "success": False,
            "error": "Not found"
        }), 404

    return (
        "404 - Page not found",
        404
    )


@APP.errorhandler(500)
def internal_error(error):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

    return (
        "500 - Internal server error",
        500
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    init_database()

    print()
    print("=" * 60)
    print("                 API MANAGER")
    print("=" * 60)
    print()
    print("Database:")
    print(DB_FILE)
    print()
    print("Dashboard:")
    print(
        f"http://127.0.0.1:{PORT}"
    )
    print()
    print("API Base:")
    print(
        f"{get_base_url()}/api/"
    )
    print()
    print("Health:")
    print(
        f"http://127.0.0.1:{PORT}/health"
    )
    print()
    print("=" * 60)
    print()

    APP.run(
        host=HOST,
        port=PORT,
        debug=False,
        threaded=True
    )
