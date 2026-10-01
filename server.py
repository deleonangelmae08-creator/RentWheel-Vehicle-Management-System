import argparse
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "rentwheel.sqlite3"
SESSION_SECONDS = 60 * 60 * 24 * 7

SEED_VEHICLES = [
    ("VEH-001", "NCR 8172", "RW-101", "Toyota", "Vios", "Silver", 2023, 1800, "Available"),
    ("VEH-002", "NCR 4521", "RW-102", "Mitsubishi", "Montero Sport", "Black", 2022, 4200, "Rented"),
    ("VEH-003", "ABC 9045", "RW-103", "Honda", "City", "White", 2024, 2200, "Available"),
    ("VEH-004", "KLM 3310", "RW-104", "Toyota", "Innova", "Gray", 2021, 3500, "Maintenance"),
    ("VEH-005", "MNO 7789", "RW-105", "Ford", "Ranger", "Blue", 2023, 3800, "Reported Issue"),
    ("VEH-006", "PQR 1108", "RW-106", "Nissan", "Almera", "Red", 2022, 1900, "Rented"),
]
SEED_CUSTOMERS = [
    ("CUS-001", "Maria", "Santos", "0917 555 0142", "maria.santos@email.test", "Makati City", "N01-23-456789"),
    ("CUS-002", "Daniel", "Cruz", "0918 555 8240", "daniel.cruz@email.test", "Quezon City", "N02-21-123456"),
    ("CUS-003", "Aisha", "Garcia", "0920 555 0931", "aisha.garcia@email.test", "Pasig City", "N03-22-654321"),
    ("CUS-004", "Leo", "Tan", "0919 555 2122", "leo.tan@email.test", "Taguig City", "N04-20-998821"),
]
SEED_RENTALS = [
    ("RNT-001", "CUS-001", "VEH-002", "ADM-001", "2026-09-26", "", "2026-10-02", "Active", "Rented"),
    ("RNT-002", "CUS-002", "VEH-006", "ADM-001", "2026-09-20", "", "2026-09-28", "Overdue", "Rented"),
    ("RNT-003", "CUS-003", "VEH-001", "ADM-001", "2026-10-04", "", "2026-10-08", "Reserved", "Available"),
    ("RNT-004", "CUS-004", "VEH-004", "ADM-001", "2026-09-10", "2026-09-14", "2026-09-14", "Completed", "Maintenance"),
]
SEED_RETURNS = [("RET-001", "RNT-004", "2026-09-14", "Needs Maintenance", 0)]
SEED_PAYMENTS = [
    ("PAY-001", "RNT-001", "2026-09-26", 3600, "Card", "Partial"),
    ("PAY-002", "RNT-002", "2026-09-20", 3800, "Cash", "Pending"),
    ("PAY-003", "RNT-004", "2026-09-14", 14000, "Bank Transfer", "Paid"),
]


class ApiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message


@contextmanager
def database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                admin_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS customers (
                customer_id TEXT PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                address TEXT NOT NULL,
                license_number TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS customer_credentials (
                customer_id TEXT PRIMARY KEY REFERENCES customers(customer_id) ON DELETE CASCADE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vehicles (
                vehicle_id TEXT PRIMARY KEY,
                plate_number TEXT NOT NULL UNIQUE,
                vehicle_number TEXT NOT NULL UNIQUE,
                brand TEXT NOT NULL,
                model TEXT NOT NULL,
                color TEXT NOT NULL,
                year INTEGER NOT NULL,
                rental_rate REAL NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rentals (
                rental_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                vehicle_id TEXT NOT NULL REFERENCES vehicles(vehicle_id),
                admin_id TEXT NOT NULL,
                rental_date TEXT NOT NULL,
                return_date TEXT NOT NULL DEFAULT '',
                return_due_date TEXT NOT NULL,
                rental_status TEXT NOT NULL,
                vehicle_status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS returns (
                return_id TEXT PRIMARY KEY,
                rental_id TEXT NOT NULL REFERENCES rentals(rental_id),
                return_date TEXT NOT NULL,
                condition_status TEXT NOT NULL,
                late_fee REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS payments (
                payment_id TEXT PRIMARY KEY,
                rental_id TEXT NOT NULL REFERENCES rentals(rental_id),
                payment_date TEXT NOT NULL,
                amount REAL NOT NULL,
                payment_method TEXT NOT NULL,
                payment_status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                role TEXT NOT NULL CHECK(role IN ('admin', 'customer')),
                user_id TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            """
        )
        if db.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0] == 0:
            db.executemany("INSERT INTO vehicles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", SEED_VEHICLES)
            db.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)", SEED_CUSTOMERS)
            db.executemany("INSERT INTO rentals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", SEED_RENTALS)
            db.executemany("INSERT INTO returns VALUES (?, ?, ?, ?, ?)", SEED_RETURNS)
            db.executemany("INSERT INTO payments VALUES (?, ?, ?, ?, ?, ?)", SEED_PAYMENTS)


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex(), digest.hex()


def verify_password(password, salt, expected_hash):
    _, actual_hash = hash_password(password, bytes.fromhex(salt))
    return hmac.compare_digest(actual_hash, expected_hash)


def next_id(db, table, column, prefix):
    identifiers = [row[0] for row in db.execute(f"SELECT {column} FROM {table}")]
    greatest = max((int(identifier.rsplit("-", 1)[-1]) for identifier in identifiers), default=0)
    return f"{prefix}-{greatest + 1:03d}"


def admin_record(row):
    return {key: row[key] for key in ("admin_id", "username", "full_name", "email")}


def customer_record(row):
    return {key: row[key] for key in ("customer_id", "first_name", "last_name", "phone_number", "email", "address", "license_number")}


def rows_as_dicts(db, table):
    return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]


def load_admin_state(db):
    return {
        "vehicles": rows_as_dicts(db, "vehicles"),
        "customers": rows_as_dicts(db, "customers"),
        "rentals": rows_as_dicts(db, "rentals"),
        "returns": rows_as_dicts(db, "returns"),
        "payments": rows_as_dicts(db, "payments"),
    }


def create_session(db, role, user_id):
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions(token, role, user_id, expires_at) VALUES (?, ?, ?, ?)",
        (token, role, user_id, time.time() + SESSION_SECONDS),
    )
    return token


class RentWheelHandler(SimpleHTTPRequestHandler):
    server_version = "RentWheel/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")

    def send_json(self, status, payload, token=None):
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if token is not None:
            max_age = SESSION_SECONDS if token else 0
            self.send_header("Set-Cookie", f"rentwheel_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}")
        self.end_headers()
        self.wfile.write(content)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1_000_000:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            raise ApiError(400, "A valid JSON request body is required.") from None
        if not isinstance(payload, dict):
            raise ApiError(400, "The request body must be a JSON object.")
        return payload

    def current_session(self, db, required_role=None):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("rentwheel_session")
        if not token:
            raise ApiError(401, "Please sign in to continue.")
        session = db.execute(
            "SELECT role, user_id FROM sessions WHERE token = ? AND expires_at > ?",
            (token.value, time.time()),
        ).fetchone()
        if not session:
            raise ApiError(401, "Your session has expired. Please sign in again.")
        if required_role and session["role"] != required_role:
            raise ApiError(403, "You do not have permission to perform this action.")
        return session

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/.vscode/index.html")
            self.end_headers()
            return
        if not path.startswith("/api/"):
            return super().do_GET()
        try:
            with database() as db:
                if path == "/api/setup":
                    exists = db.execute("SELECT 1 FROM admins LIMIT 1").fetchone() is not None
                    return self.send_json(200, {"admin_setup_required": not exists})
                if path == "/api/session":
                    session = self.current_session(db)
                    if session["role"] == "admin":
                        row = db.execute("SELECT * FROM admins WHERE admin_id = ?", (session["user_id"],)).fetchone()
                        user = admin_record(row)
                    else:
                        row = db.execute("SELECT * FROM customers WHERE customer_id = ?", (session["user_id"],)).fetchone()
                        user = customer_record(row)
                    state = load_admin_state(db) if session["role"] == "admin" else self.load_customer_state(db, session["user_id"])
                    return self.send_json(200, {"role": session["role"], "user": user, "state": state})
                if path == "/api/admin/state":
                    self.current_session(db, "admin")
                    return self.send_json(200, load_admin_state(db))
                raise ApiError(404, "API route not found.")
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "API route not found."})
        try:
            payload = self.read_json()
            with database() as db:
                if path == "/api/admin/setup":
                    return self.admin_setup(db, payload)
                if path == "/api/admin/login":
                    return self.admin_login(db, payload)
                if path == "/api/customer/register":
                    return self.customer_register(db, payload)
                if path == "/api/customer/login":
                    return self.customer_login(db, payload)
                if path == "/api/customer/rentals":
                    return self.customer_rental(db, payload)
                if path == "/api/admin/state":
                    self.current_session(db, "admin")
                    self.save_admin_state(db, payload)
                    return self.send_json(200, {"saved": True})
                if path == "/api/logout":
                    cookie = SimpleCookie(self.headers.get("Cookie", ""))
                    token = cookie.get("rentwheel_session")
                    if token:
                        db.execute("DELETE FROM sessions WHERE token = ?", (token.value,))
                    return self.send_json(200, {"signed_out": True}, token="")
                raise ApiError(404, "API route not found.")
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except sqlite3.IntegrityError as error:
            self.send_json(409, {"error": "That account or record already exists."})
        except (KeyError, TypeError, ValueError):
            self.send_json(400, {"error": "Please check the submitted information and try again."})

    def admin_setup(self, db, payload):
        if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            raise ApiError(409, "The administrator account has already been initialized.")
        username = str(payload.get("username", "")).strip()
        full_name = str(payload.get("full_name", "")).strip()
        email = str(payload.get("email", "")).strip().lower()
        password = str(payload.get("password", ""))
        if not username or not full_name or "@" not in email or len(password) < 8:
            raise ApiError(400, "Enter a name, username, valid email, and password with at least 8 characters.")
        salt, password_hash = hash_password(password)
        admin_id = next_id(db, "admins", "admin_id", "ADM")
        db.execute(
            "INSERT INTO admins(admin_id, username, full_name, email, password_salt, password_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (admin_id, username, full_name, email, salt, password_hash),
        )
        token = create_session(db, "admin", admin_id)
        user = admin_record(db.execute("SELECT * FROM admins WHERE admin_id = ?", (admin_id,)).fetchone())
        self.send_json(201, {"role": "admin", "user": user, "state": load_admin_state(db)}, token)

    def admin_login(self, db, payload):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        row = db.execute("SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
        if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
            raise ApiError(401, "The administrator username or password is incorrect.")
        token = create_session(db, "admin", row["admin_id"])
        self.send_json(200, {"role": "admin", "user": admin_record(row), "state": load_admin_state(db)}, token)

    def customer_register(self, db, payload):
        record = {
            "first_name": str(payload.get("first_name", "")).strip(),
            "last_name": str(payload.get("last_name", "")).strip(),
            "phone_number": str(payload.get("phone_number", "")).strip(),
            "email": str(payload.get("email", "")).strip().lower(),
            "address": str(payload.get("address", "")).strip(),
            "license_number": str(payload.get("license_number", "")).strip(),
        }
        password = str(payload.get("password", ""))
        if not all(record.values()) or "@" not in record["email"] or len(password) < 8:
            raise ApiError(400, "Complete all fields and use a valid email and a password with at least 8 characters.")
        if db.execute("SELECT 1 FROM customers WHERE email = ? COLLATE NOCASE", (record["email"],)).fetchone():
            raise ApiError(409, "An account already uses this email address.")
        customer_id = next_id(db, "customers", "customer_id", "CUS")
        db.execute(
            "INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)",
            (customer_id, record["first_name"], record["last_name"], record["phone_number"], record["email"], record["address"], record["license_number"]),
        )
        salt, password_hash = hash_password(password)
        db.execute("INSERT INTO customer_credentials VALUES (?, ?, ?)", (customer_id, salt, password_hash))
        token = create_session(db, "customer", customer_id)
        state = self.load_customer_state(db, customer_id)
        user = customer_record(db.execute("SELECT * FROM customers WHERE customer_id = ?", (customer_id,)).fetchone())
        self.send_json(201, {"role": "customer", "user": user, "state": state}, token)

    def customer_login(self, db, payload):
        email = str(payload.get("email", "")).strip().lower()
        password = str(payload.get("password", ""))
        row = db.execute(
            "SELECT c.*, a.password_salt, a.password_hash FROM customers c JOIN customer_credentials a USING(customer_id) WHERE c.email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
            raise ApiError(401, "The email or password is incorrect.")
        token = create_session(db, "customer", row["customer_id"])
        self.send_json(200, {"role": "customer", "user": customer_record(row), "state": self.load_customer_state(db, row["customer_id"])}, token)

    def load_customer_state(self, db, customer_id):
        state = load_admin_state(db)
        state["customers"] = [customer_record(db.execute("SELECT * FROM customers WHERE customer_id = ?", (customer_id,)).fetchone())]
        state["rentals"] = [dict(row) for row in db.execute("SELECT * FROM rentals WHERE customer_id = ? ORDER BY rental_date DESC", (customer_id,))]
        state["returns"] = []
        state["payments"] = []
        return state

    def customer_rental(self, db, payload):
        session = self.current_session(db, "customer")
        vehicle_id = str(payload.get("vehicle_id", ""))
        start = str(payload.get("rental_date", ""))
        due = str(payload.get("return_due_date", ""))
        if not start or not due or due <= start:
            raise ApiError(400, "Choose a return date after the rental date.")
        db.execute("BEGIN IMMEDIATE")
        vehicle = db.execute("SELECT status FROM vehicles WHERE vehicle_id = ?", (vehicle_id,)).fetchone()
        if not vehicle or vehicle["status"] != "Available":
            raise ApiError(409, "This vehicle is no longer available.")
        rental_id = next_id(db, "rentals", "rental_id", "RNT")
        admin_id = db.execute("SELECT admin_id FROM admins ORDER BY created_at LIMIT 1").fetchone()[0]
        db.execute(
            "INSERT INTO rentals VALUES (?, ?, ?, ?, ?, '', ?, 'Reserved', 'Reserved')",
            (rental_id, session["user_id"], vehicle_id, admin_id, start, due),
        )
        db.execute("UPDATE vehicles SET status = 'Reserved' WHERE vehicle_id = ?", (vehicle_id,))
        self.send_json(201, {"state": self.load_customer_state(db, session["user_id"])})

    def save_admin_state(self, db, state):
        required = ("vehicles", "customers", "rentals", "returns", "payments")
        if any(not isinstance(state.get(key), list) for key in required):
            raise ApiError(400, "The submitted database state is incomplete.")
        db.execute("DELETE FROM payments")
        db.execute("DELETE FROM returns")
        db.execute("DELETE FROM rentals")
        for customer in state["customers"]:
            db.execute(
                "INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(customer_id) DO UPDATE SET first_name=excluded.first_name, last_name=excluded.last_name, phone_number=excluded.phone_number, email=excluded.email, address=excluded.address, license_number=excluded.license_number",
                tuple(customer[key] for key in ("customer_id", "first_name", "last_name", "phone_number", "email", "address", "license_number")),
            )
        for vehicle in state["vehicles"]:
            db.execute(
                "INSERT INTO vehicles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(vehicle_id) DO UPDATE SET plate_number=excluded.plate_number, vehicle_number=excluded.vehicle_number, brand=excluded.brand, model=excluded.model, color=excluded.color, year=excluded.year, rental_rate=excluded.rental_rate, status=excluded.status",
                tuple(vehicle[key] for key in ("vehicle_id", "plate_number", "vehicle_number", "brand", "model", "color", "year", "rental_rate", "status")),
            )
        customer_ids = [item["customer_id"] for item in state["customers"]]
        vehicle_ids = [item["vehicle_id"] for item in state["vehicles"]]
        if customer_ids:
            db.execute(f"DELETE FROM customers WHERE customer_id NOT IN ({','.join('?' for _ in customer_ids)})", customer_ids)
        if vehicle_ids:
            db.execute(f"DELETE FROM vehicles WHERE vehicle_id NOT IN ({','.join('?' for _ in vehicle_ids)})", vehicle_ids)
        for rental in state["rentals"]:
            db.execute(
                "INSERT INTO rentals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(rental[key] for key in ("rental_id", "customer_id", "vehicle_id", "admin_id", "rental_date", "return_date", "return_due_date", "rental_status", "vehicle_status")),
            )
        for item in state["returns"]:
            db.execute(
                "INSERT INTO returns VALUES (?, ?, ?, ?, ?)",
                tuple(item[key] for key in ("return_id", "rental_id", "return_date", "condition_status", "late_fee")),
            )
        for item in state["payments"]:
            db.execute(
                "INSERT INTO payments VALUES (?, ?, ?, ?, ?, ?)",
                tuple(item[key] for key in ("payment_id", "rental_id", "payment_date", "amount", "payment_method", "payment_status")),
            )


def main():
    global DATABASE
    parser = argparse.ArgumentParser(description="Run the RentWheel SQLite-backed web application.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--database", type=Path, default=DATABASE)
    args = parser.parse_args()
    DATABASE = args.database.resolve()
    initialize_database()
    server = ThreadingHTTPServer((args.host, args.port), RentWheelHandler)
    print(f"RentWheel is running at http://localhost:{args.port}/")
    print(f"SQLite database: {DATABASE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nRentWheel server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
