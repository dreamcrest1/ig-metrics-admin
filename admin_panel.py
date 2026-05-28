import os
import sys
import json
import time
import hmac
import hashlib
import base64
import threading
import webbrowser
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_from_directory

app = Flask(__name__)

# ── DATA PERSISTENCE RESOLUTION FOR LOCAL & CLOUD ──────────────────────────
# Try to import psycopg2 for PostgreSQL support (used for persistent cloud hosting like Render)
try:
    import psycopg2
    import psycopg2.pool
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# Detect cloud environment (Render sets DATABASE_URL and PORT)
IS_CLOUD = bool(os.environ.get("DATABASE_URL") or os.environ.get("RENDER"))

if getattr(sys, 'frozen', False):
    DB_PATH = os.path.join(os.path.dirname(sys.executable), "admin_db.json")
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_db.json")

LICENSE_SECRET = b"IG_METRICS_PRO_SECRET_2026"

# ── CONNECTION POOL (initialized lazily) ────────────────────────────────────
_pg_pool = None

def get_pg_pool():
    global _pg_pool
    db_url = os.environ.get("DATABASE_URL")
    if not db_url or not HAS_POSTGRES:
        return None
    if _pg_pool is None:
        try:
            _pg_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1, maxconn=5, dsn=db_url,
                connect_timeout=10
            )
        except Exception as e:
            print(f"[POOL INIT ERROR] {e}")
            return None
    return _pg_pool

# ── DATABASE HELPERS ────────────────────────────────────────────────────────

_pg_table_ready = False

def _ensure_pg_table(cur):
    """Migrate from old SERIAL-based table to single-row UPSERT pattern if needed."""
    global _pg_table_ready
    if _pg_table_ready:
        return
    
    try:
        # Check if old table exists with SERIAL primary key
        cur.execute("""
            SELECT column_default FROM information_schema.columns
            WHERE table_name = 'admin_store' AND column_name = 'id';
        """)
        row = cur.fetchone()
        
        if row and row[0] and 'nextval' in str(row[0]):
            # Old SERIAL table detected — migrate data
            print("[MIGRATION] Migrating admin_store from SERIAL to single-row UPSERT schema...")
            cur.execute("SELECT data FROM admin_store ORDER BY id DESC LIMIT 1;")
            old_data = cur.fetchone()
            cur.execute("DROP TABLE admin_store;")
            cur.execute("""
                CREATE TABLE admin_store (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    data TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            if old_data:
                cur.execute("INSERT INTO admin_store (id, data) VALUES (1, %s);", (old_data[0],))
            print("[MIGRATION] Migration complete.")
        elif row is None:
            # Table doesn't exist yet — create fresh
            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_store (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    data TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
        # else: table already has the new schema, nothing to do
    except Exception as e:
        # If schema check fails, just try to create the table
        print(f"[TABLE SETUP] Creating table: {e}")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_store (
                id INTEGER PRIMARY KEY DEFAULT 1,
                data TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT NOW()
            );
        """)
    
    _pg_table_ready = True

def load_db():
    pool = get_pg_pool()
    if pool:
        conn = None
        try:
            conn = pool.getconn()
            cur = conn.cursor()
            _ensure_pg_table(cur)
            conn.commit()
            cur.execute("SELECT data FROM admin_store WHERE id = 1;")
            row = cur.fetchone()
            cur.close()
            if row:
                return json.loads(row[0])
            return {"clients": []}
        except Exception as e:
            print(f"[POSTGRES LOAD ERROR] Falling back to local JSON: {e}")
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if conn and pool:
                try:
                    pool.putconn(conn)
                except Exception:
                    pass

    if not os.path.exists(DB_PATH):
        return {"clients": []}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "clients" not in data:
                data = {"clients": []}
            return data
    except Exception:
        return {"clients": []}

def save_db(data):
    pool = get_pg_pool()
    if pool:
        conn = None
        try:
            conn = pool.getconn()
            cur = conn.cursor()
            _ensure_pg_table(cur)
            data_str = json.dumps(data)
            # UPSERT single row — no table bloat
            cur.execute("""
                INSERT INTO admin_store (id, data, updated_at)
                VALUES (1, %s, NOW())
                ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW();
            """, (data_str,))
            conn.commit()
            cur.close()
            return
        except Exception as e:
            print(f"[POSTGRES SAVE ERROR] Falling back to local JSON: {e}")
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if conn and pool:
                try:
                    pool.putconn(conn)
                except Exception:
                    pass

    try:
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[SYSTEM ERROR] Could not save database: {e}")

# ── KEYGEN LOGIC ────────────────────────────────────────────────────────────

def generate_key_string(days, tool="ig-master-suite"):
    expiry_date = datetime.now().date() + timedelta(days=days)
    expiry_str = expiry_date.strftime("%Y-%m-%d")
    
    # Random nonce to ensure every key is unique (fixes duplicate key collision bug)
    nonce = hashlib.sha256(os.urandom(32)).hexdigest()[:8]
    
    # Include tool target AND nonce in the signature for cryptographic binding
    sig_payload = f"{expiry_str}|{tool}|{nonce}"
    sig = hmac.new(LICENSE_SECRET, sig_payload.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    
    payload = f"{expiry_str}|{tool}|{nonce}|{sig}"
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8'), expiry_str

def check_key_signature(key_str, tool="ig-master-suite"):
    try:
        decoded = base64.b64decode(key_str.strip().encode('utf-8')).decode('utf-8')
        if "|" not in decoded:
            return False, "Invalid format"
        
        parts = decoded.split("|")
        if len(parts) == 4:
            # New format: expiry|tool|nonce|sig
            expiry_str, key_tool, nonce, sig = parts
            sig_payload = f"{expiry_str}|{key_tool}|{nonce}"
            expected_sig = hmac.new(LICENSE_SECRET, sig_payload.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(sig, expected_sig):
                return False, "Signature verification failed"
        elif len(parts) == 3:
            # Legacy format: expiry|tool|sig (no nonce, deterministic)
            expiry_str, key_tool, sig = parts
            sig_payload = f"{expiry_str}|{key_tool}"
            expected_sig = hmac.new(LICENSE_SECRET, sig_payload.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(sig, expected_sig):
                return False, "Signature verification failed"
        elif len(parts) == 2:
            # Very old legacy format: expiry|sig (no tool, no nonce)
            expiry_str, sig = parts
            key_tool = "ig-master-suite"
            legacy_expected_sig = hmac.new(LICENSE_SECRET, expiry_str.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(sig, legacy_expected_sig):
                return False, "Signature verification failed"
        else:
            return False, "Invalid key format"
            
        # Verify tool target (universal keys work for everything)
        if key_tool != "all" and key_tool != tool:
            return False, f"Key target mismatch. Intended for '{key_tool}'"
            
        return True, expiry_str
    except Exception:
        return False, "Corrupt key structure"

# ── PREMIUM REDESIGNED HTML TEMPLATE ───────────────────────────────────────────

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dreamcrest Enterprise Control Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060609;
            --bg-surface: rgba(10, 10, 16, 0.65);
            --bg-card: rgba(22, 22, 34, 0.45);
            --border-glow: rgba(99, 102, 241, 0.25);
            --border-light: rgba(255, 255, 255, 0.06);
            
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --primary-gradient: linear-gradient(135deg, #6366f1, #7c3aed, #d946ef);
            
            --emerald: #10b981;
            --emerald-glow: rgba(16, 185, 129, 0.3);
            
            --rose: #ef4444;
            --rose-glow: rgba(239, 68, 68, 0.3);
            
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --text-dark: #6b7280;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        /* CUSTOM SCROLLBARS */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(99, 102, 241, 0.25);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(99, 102, 241, 0.5);
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(at 8% 12%, rgba(99, 102, 241, 0.1) 0px, transparent 45%),
                radial-gradient(at 92% 88%, rgba(217, 70, 239, 0.06) 0px, transparent 45%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            overflow-x: hidden;
        }

        .dashboard-wrapper {
            width: 100%;
            max-width: 1300px;
            animation: fadeInPage 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes fadeInPage {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* HEADER SECTION */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 35px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-light);
        }

        .header-brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            background: var(--primary-gradient);
            background-size: 200% 200%;
            animation: gradientAnim 6s ease infinite;
            width: 46px;
            height: 46px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            font-weight: bold;
            box-shadow: 0 0 20px var(--primary-glow);
        }

        .brand-text h1 {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 0.5px;
            background: linear-gradient(to right, #ffffff, #c7d2fe, #f472b6);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shineText 5s linear infinite;
        }

        @keyframes shineText {
            to { background-position: 200% center; }
        }

        .brand-text p {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-top: 2px;
        }

        .server-status-badge {
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 8px 16px;
            border-radius: 30px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 600;
            color: #34d399;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.05);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--emerald);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--emerald);
            animation: pulse-green 2s infinite;
        }

        @keyframes pulse-green {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.6); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* METRICS PANEL */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }

        .metric-card {
            background: linear-gradient(135deg, rgba(22, 22, 34, 0.4), rgba(13, 13, 21, 0.65));
            border: 1px solid var(--border-light);
            border-radius: 18px;
            padding: 24px;
            backdrop-filter: blur(20px) saturate(180%);
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }

        .metric-card:hover {
            border-color: var(--border-glow);
            transform: translateY(-4px) scale(1.02);
            box-shadow: 0 15px 35px rgba(99, 102, 241, 0.15);
        }

        .metric-info h3 {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 800;
            color: #ffffff;
            letter-spacing: -0.5px;
        }

        .metric-icon {
            width: 52px;
            height: 52px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: inset 0 0 12px rgba(255, 255, 255, 0.05);
        }

        .m-keys { background: rgba(99, 102, 241, 0.08); color: var(--primary); border: 1px solid rgba(99, 102, 241, 0.15); }
        .m-active { background: rgba(16, 185, 129, 0.08); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.15); }
        .m-disabled { background: rgba(239, 68, 68, 0.08); color: var(--rose); border: 1px solid rgba(239, 68, 68, 0.15); }
        .m-online { background: rgba(245, 158, 11, 0.08); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.15); }

        /* CONTENT WORKSPACE GRID */
        .workspace-grid {
            display: grid;
            grid-template-columns: 380px 1fr;
            gap: 30px;
        }

        @media (max-width: 1080px) {
            .workspace-grid {
                grid-template-columns: 1fr;
            }
        }

        .panel-glass {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: 20px;
            backdrop-filter: blur(20px) saturate(180%);
            padding: 30px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.55);
            transition: border-color 0.3s;
        }

        .panel-glass:focus-within {
            border-color: rgba(99, 102, 241, 0.2);
        }

        .panel-glass h2 {
            font-size: 19px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 14px;
        }

        /* FORM ELEMENTS */
        .form-group {
            margin-bottom: 24px;
        }

        .form-group label {
            display: block;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .input-control {
            width: 100%;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 12px;
            padding: 14px 16px;
            color: #ffffff;
            font-family: inherit;
            font-size: 14px;
            outline: none;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .input-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
            background: rgba(0, 0, 0, 0.55);
        }

        .btn-action {
            width: 100%;
            background: var(--primary-gradient);
            background-size: 200% 200%;
            animation: gradientAnim 8s ease infinite;
            border: none;
            border-radius: 12px;
            padding: 15px 24px;
            color: #ffffff;
            font-family: inherit;
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.35);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        @keyframes gradientAnim {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .btn-action:hover {
            transform: translateY(-2px);
            filter: brightness(1.15);
            box-shadow: 0 10px 25px rgba(139, 92, 246, 0.55);
        }

        .btn-action:active {
            transform: translateY(1px);
        }

        /* KEY RESULTS BOX */
        .key-reveal-box {
            margin-top: 24px;
            background: rgba(99, 102, 241, 0.05);
            border: 1px solid rgba(99, 102, 241, 0.25);
            border-radius: 14px;
            padding: 20px;
            animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .reveal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 8px;
        }

        .reveal-title {
            color: #a5b4fc;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .btn-copy {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            padding: 6px 12px;
            cursor: pointer;
            transition: all 0.2s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-copy:hover {
            background: var(--primary);
            border-color: transparent;
            box-shadow: 0 0 12px rgba(99, 102, 241, 0.4);
        }

        /* CLIENT LIST CONTROLS */
        .table-toolbar {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            margin-bottom: 24px;
        }

        @media (max-width: 600px) {
            .table-toolbar {
                flex-direction: column;
                align-items: stretch;
            }
        }

        .search-wrapper {
            position: relative;
            flex-grow: 1;
        }

        .search-input {
            width: 100%;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.06);
            padding: 13px 16px;
            padding-left: 44px;
            border-radius: 12px;
            color: #ffffff;
            font-size: 14px;
            outline: none;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .search-input:focus {
            border-color: var(--primary);
            background: rgba(0, 0, 0, 0.45);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .search-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-dark);
            font-size: 16px;
            pointer-events: none;
        }

        .filter-group {
            display: flex;
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 5px;
            gap: 4px;
        }

        .filter-btn {
            background: transparent;
            border: none;
            padding: 8px 16px;
            color: var(--text-muted);
            font-family: inherit;
            font-size: 12px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .filter-btn.active {
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            border: 1px solid rgba(99, 102, 241, 0.25);
        }

        .filter-btn:hover:not(.active) {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.04);
        }

        /* DATA TABLE STYLE */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
            border-radius: 14px;
            border: 1px solid rgba(255, 255, 255, 0.06);
            background: rgba(0, 0, 0, 0.2);
            box-shadow: inset 0 4px 20px rgba(0, 0, 0, 0.3);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }

        th {
            background: rgba(14, 14, 24, 0.7);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            padding: 16px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }

        td {
            padding: 18px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            color: var(--text-main);
            vertical-align: middle;
        }

        tr {
            transition: background-color 0.2s;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        .client-name-cell {
            font-weight: 600;
            color: #ffffff;
            font-size: 14.5px;
        }

        .client-key-code {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.06);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            color: #d1d5db;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-copy-table {
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 12px;
            transition: color 0.1s;
        }

        .btn-copy-table:hover {
            color: #ffffff;
        }

        .badge-status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .status-dot-mini {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .bg-active {
            background: rgba(16, 185, 129, 0.07);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: #34d399;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.1);
        }
        .bg-active .status-dot-mini {
            background: var(--emerald);
            box-shadow: 0 0 6px var(--emerald);
        }

        .bg-disabled {
            background: rgba(239, 68, 68, 0.07);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #f87171;
        }
        .bg-disabled .status-dot-mini {
            background: var(--rose);
        }

        .expiry-cell {
            font-weight: 500;
            color: #e5e7eb;
        }

        .ip-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: #9ca3af;
        }

        .ip-none {
            color: var(--text-dark);
            font-style: italic;
            font-size: 12px;
        }

        /* TABLE ACTION BUTTONS */
        .actions-group {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .btn-action-sm {
            padding: 8px 14px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            letter-spacing: 0.5px;
        }

        .btn-sm-toggle-off {
            background: rgba(239, 68, 68, 0.1);
            color: var(--rose);
            border: 1px solid rgba(239, 68, 68, 0.15);
        }
        .btn-sm-toggle-off:hover {
            background: var(--rose);
            color: #ffffff;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.35);
        }

        .btn-sm-toggle-on {
            background: rgba(16, 185, 129, 0.1);
            color: var(--emerald);
            border: 1px solid rgba(16, 185, 129, 0.15);
        }
        .btn-sm-toggle-on:hover {
            background: var(--emerald);
            color: #ffffff;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.35);
        }

        .btn-sm-delete {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-muted);
            border: 1px solid var(--border-light);
        }
        .btn-sm-delete:hover {
            background: rgba(239, 68, 68, 0.2);
            color: #ffffff;
            border-color: rgba(239, 68, 68, 0.3);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
        }

        .empty-row-state {
            text-align: center;
            color: var(--text-dark);
            padding: 60px 20px;
            font-style: italic;
        }

        /* TOAST FLOATING BANNER */
        .toast-container {
            position: fixed;
            bottom: 24px;
            right: 24px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            z-index: 1000;
        }

        .toast-alert {
            background: rgba(13, 13, 21, 0.95);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-left: 4px solid var(--primary);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
            color: #ffffff;
            padding: 14px 20px;
            border-radius: 10px;
            font-size: 13.5px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 280px;
            backdrop-filter: blur(10px);
            animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes slideIn {
            from { transform: translateX(120%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .toast-alert.hide {
            animation: slideOut 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(120%); opacity: 0; }
        }
    </style>
</head>
<body>

    <div class="dashboard-wrapper">
        <header>
            <div class="header-brand">
                <img src="/logo.png" alt="Logo" style="width: 44px; height: 44px; border-radius: 10px; box-shadow: 0 0 15px rgba(99, 102, 241, 0.35);" onerror="this.style.display='none'; document.getElementById('fallback-icon').style.display='flex';" />
                <div id="fallback-icon" class="brand-icon" style="display: none;">⚡</div>
                <div class="brand-text">
                    <h1>Dreamcrest Enterprise Control Center</h1>
                    <p>Enterprise Universal Key Control Panel</p>
                </div>
            </div>
            <div class="server-status-badge">
                <div class="status-dot"></div>
                <span>Server Online</span>
            </div>
        </header>

        <!-- KPI METRICS GRID -->
        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-info">
                    <h3>Total Issued Licenses</h3>
                    <div id="stat-total-keys" class="metric-value">0</div>
                </div>
                <div class="metric-icon m-keys">🔑</div>
            </div>
            <div class="metric-card">
                <div class="metric-info">
                    <h3>Active Accounts</h3>
                    <div id="stat-active-keys" class="metric-value">0</div>
                </div>
                <div class="metric-icon m-active">✅</div>
            </div>
            <div class="metric-card">
                <div class="metric-info">
                    <h3>Suspended Access</h3>
                    <div id="stat-disabled-keys" class="metric-value">0</div>
                </div>
                <div class="metric-icon m-disabled">🛑</div>
            </div>
            <div class="metric-card">
                <div class="metric-info">
                    <h3>Online IPs Connected</h3>
                    <div id="stat-ips-count" class="metric-value">0</div>
                </div>
                <div class="metric-icon m-online">💻</div>
            </div>
        </section>

        <!-- MAIN SPLIT WORKSPACE -->
        <main class="workspace-grid">
            
            <!-- LEFT PANEL: KEYGEN -->
            <section class="panel-glass">
                <h2>🔑 Create Activation Key</h2>
                
                <div class="form-group">
                    <label for="txt-client-name">Licensee / Client Name</label>
                    <input type="text" id="txt-client-name" class="input-control" placeholder="e.g. Acme Corp - Machine 1" autocomplete="off">
                </div>

                <div class="form-group">
                    <label>Target Application</label>
                    <div style="background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.25); color: #a5b4fc; padding: 12px 14px; border-radius: 10px; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                        <span>🛡️</span> All Access (Universal Key)
                    </div>
                </div>

                <div class="form-group">
                    <label for="txt-batch-count">Batch Count (Keys to Generate)</label>
                    <input type="number" id="txt-batch-count" class="input-control" value="1" min="1" max="100" placeholder="Number of keys...">
                </div>

                <div class="form-group">
                    <label for="txt-duration">License Duration (Days)</label>
                    <input type="number" id="txt-duration" class="input-control" value="30" min="1" max="36500" placeholder="Enter number of days...">
                    <div style="display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap;">
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(1)">1d</button>
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(7)">7d</button>
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(30)">30d</button>
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(90)">90d</button>
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(365)">1 Year</button>
                        <button type="button" class="btn-copy" style="background: rgba(255,255,255,0.05); padding: 6px 10px;" onclick="setDurationPreset(27000)">Lifetime</button>
                    </div>
                </div>

                <button class="btn-action" onclick="generateKey()">
                    <span>Register & Generate Key</span>
                </button>

                <!-- DISPLAY DYNAMIC REVEAL OF GENERATED KEYS -->
                <div id="new-key-box" class="key-reveal-box" style="display: none;">
                    <div class="reveal-header">
                        <span class="reveal-title" id="reveal-title-text">Licenses Registered</span>
                        <div style="display: flex; gap: 6px;">
                            <button class="btn-copy" onclick="copyAllKeys()">Copy All</button>
                            <button class="btn-copy" style="background: var(--primary);" onclick="downloadKeysTxt()">Download TXT</button>
                        </div>
                    </div>
                    <div id="new-keys-container" style="display: flex; flex-direction: column; gap: 8px; max-height: 200px; overflow-y: auto; margin-top: 10px;">
                        <!-- Keys will be dynamically inserted here -->
                    </div>
                </div>
            </section>

            <!-- RIGHT PANEL: CLIENT DATABASE -->
            <section class="panel-glass">
                <h2>💻 Active P2P Clients</h2>

                <div class="table-toolbar">
                    <div class="search-wrapper" style="flex: 1.5; min-width: 200px;">
                        <span class="search-icon">🔍</span>
                        <input type="text" id="txt-search" class="search-input" placeholder="Search name, key, device, or IP..." onkeyup="filterClientsTable()">
                    </div>
                    <div style="flex: 1; min-width: 150px;">
                        <select id="sel-filter-tool" class="input-control" style="padding: 10px 14px; background: rgba(0,0,0,0.35); font-size: 13.5px;" onchange="filterClientsTable()">
                            <option value="all">All Applications</option>
                            <option value="ig-master-suite">IG Master Suite</option>
                            <option value="whatsapp-bulk-sender">Dreamcrest WhatsApp Sender</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <button id="filter-all" class="filter-btn active" onclick="setFilter('all')">All</button>
                        <button id="filter-active" class="filter-btn" onclick="setFilter('active')">Active</button>
                        <button id="filter-disabled" class="filter-btn" onclick="setFilter('disabled')">Suspended</button>
                    </div>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Identifier (App Target)</th>
                                <th>License Key</th>
                                <th>Expiry Date</th>
                                <th>Device Link / Last Seen IP</th>
                                <th>Access status</th>
                                <th>Control Switch</th>
                            </tr>
                        </thead>
                        <tbody id="clients-tbody">
                            <tr>
                                <td colspan="6" class="empty-row-state">Loading client data...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
    </div>

    <!-- TOAST ALERTS SYSTEM -->
    <div id="toast-container" class="toast-container"></div>

    <script>
        // Global variables for search & status filters
        let activeFilter = 'all';
        let clientsList = [];

        function showToast(message) {
            const container = document.getElementById('toast-container');
            const alert = document.createElement('div');
            alert.className = 'toast-alert';
            alert.innerHTML = `<span>🔔</span> <span>${message}</span>`;
            container.appendChild(alert);

            // Trigger slide out after 3.2 seconds
            setTimeout(() => {
                alert.classList.add('hide');
                setTimeout(() => {
                    alert.remove();
                }, 300);
            }, 3200);
        }


        function copyToClipboard(elementId) {
            const copyText = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(copyText).then(() => {
                showToast("Key copied to clipboard!");
            }).catch(err => {
                console.error("Copy failed", err);
            });
        }

        function copyTextDirectly(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast("Copied to clipboard!");
            }).catch(err => {
                console.error("Copy failed", err);
            });
        }

        async function fetchAPI(url, data = null, method = 'GET') {
            const opts = { method: method };
            if (data) {
                opts.headers = { 'Content-Type': 'application/json' };
                opts.body = JSON.stringify(data);
            }
            try {
                const resp = await fetch(url, opts);
                return await resp.json();
            } catch (e) {
                console.error("API error", e);
                return { status: 'error', error: e.toString() };
            }
        }

        function setDurationPreset(days) {
            document.getElementById('txt-duration').value = days;
        }

        let generatedKeysList = [];

        async function generateKey() {
            const btn = document.querySelector('.btn-action');
            const nameInput = document.getElementById('txt-client-name');
            const name = nameInput.value.trim() || "Operations Client";
            const daysInput = document.getElementById('txt-duration');
            const days = parseInt(daysInput.value) || 30;
            const batchInput = document.getElementById('txt-batch-count');
            const count = parseInt(batchInput.value) || 1;
            
            // Show loading state
            btn.disabled = true;
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span>⏳ Generating...</span>';
            
            try {
                const res = await fetchAPI('/api/generate_key', { name: name, days: days, count: count }, 'POST');
                if (res.status === 'ok') {
                    generatedKeysList = res.keys || [res.key];
                    
                    const container = document.getElementById('new-keys-container');
                    container.innerHTML = '';
                    
                    generatedKeysList.forEach((k, idx) => {
                        const keyDiv = document.createElement('div');
                        keyDiv.style.cssText = 'display:flex;align-items:center;justify-content:space-between;background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.05);padding:8px 12px;border-radius:8px;gap:8px;';
                        
                        const codeEl = document.createElement('code');
                        codeEl.style.cssText = "font-family:'JetBrains Mono',monospace;font-size:12px;color:#ffffff;word-break:break-all;user-select:all;flex-grow:1;text-align:left;";
                        codeEl.textContent = k;
                        
                        const copyBtn = document.createElement('button');
                        copyBtn.className = 'btn-copy';
                        copyBtn.style.cssText = 'padding:2px 6px;font-size:10px;flex-shrink:0;';
                        copyBtn.textContent = 'Copy';
                        copyBtn.onclick = () => copyTextDirectly(k);
                        
                        keyDiv.appendChild(codeEl);
                        keyDiv.appendChild(copyBtn);
                        container.appendChild(keyDiv);
                    });
                    
                    document.getElementById('reveal-title-text').innerText = `${generatedKeysList.length} License${generatedKeysList.length > 1 ? 's' : ''} Registered`;
                    document.getElementById('new-key-box').style.display = 'block';
                    nameInput.value = '';
                    showToast(`${generatedKeysList.length} new key${generatedKeysList.length > 1 ? 's' : ''} generated!`);
                    loadClients();
                } else {
                    showToast("⚠️ " + (res.error || "Unknown server error"));
                    alert("Failed to generate key: " + (res.error || JSON.stringify(res)));
                }
            } catch (e) {
                showToast("⚠️ Network error: " + e.toString());
                alert("Network error generating key: " + e.toString());
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }

        function copyAllKeys() {
            if (generatedKeysList.length === 0) return;
            const keysStr = generatedKeysList.join('\\n');
            navigator.clipboard.writeText(keysStr).then(() => {
                showToast("All keys copied to clipboard!");
            }).catch(err => {
                console.error("Copy failed", err);
            });
        }

        function downloadKeysTxt() {
            if (generatedKeysList.length === 0) return;
            const keysStr = generatedKeysList.join('\\n');
            const blob = new Blob([keysStr], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dreamcrest_licenses_${new Date().toISOString().slice(0,10)}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast("Keys text file downloaded!");
        }

        async function toggleStatus(key) {
            const res = await fetchAPI('/api/toggle_status', { key: key }, 'POST');
            if (res.status === 'ok') {
                showToast("Access state updated instantly!");
                loadClients();
            }
        }

        async function deleteClient(key) {
            if (confirm("Are you sure you want to completely delete this license key? The client will be permanently locked out and removed from database.")) {
                const res = await fetchAPI('/api/delete_client', { key: key }, 'POST');
                if (res.status === 'ok') {
                    showToast("License deleted and revoked.");
                    loadClients();
                }
            }
        }

        async function resetDeviceLock(key) {
            if (confirm("Reset hardware lock for this license key? The client will be allowed to activate on a new machine next time they open the application.")) {
                const res = await fetchAPI('/api/reset_device', { key: key }, 'POST');
                if (res.status === 'ok') {
                    showToast("Device activation binding reset successfully.");
                    loadClients();
                }
            }
        }

        function setFilter(filterType) {
            activeFilter = filterType;
            // update active tab styling
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(`filter-${filterType}`).classList.add('active');
            renderTable();
        }

        function filterClientsTable() {
            renderTable();
        }

        function updateKPIs() {
            const total = clientsList.length;
            const active = clientsList.filter(c => c.status === 'active').length;
            const disabled = clientsList.filter(c => c.status === 'disabled').length;
            
            // Count unique non-null IP addresses
            const uniqueIPs = new Set(clientsList.map(c => c.last_ip).filter(ip => ip !== null && ip !== undefined && ip !== ""));
            
            document.getElementById('stat-total-keys').innerText = total;
            document.getElementById('stat-active-keys').innerText = active;
            document.getElementById('stat-disabled-keys').innerText = disabled;
            document.getElementById('stat-ips-count').innerText = uniqueIPs.size;
        }

        function renderTable() {
            const tbody = document.getElementById('clients-tbody');
            const searchQuery = document.getElementById('txt-search').value.toLowerCase().trim();
            const selectedTool = document.getElementById('sel-filter-tool').value;
            
            // 1. Filter by status tabs
            let filtered = clientsList;
            if (activeFilter === 'active') {
                filtered = clientsList.filter(c => c.status === 'active');
            } else if (activeFilter === 'disabled') {
                filtered = clientsList.filter(c => c.status === 'disabled');
            }
            
            // 1b. Filter by target application dropdown
            if (selectedTool !== 'all') {
                filtered = filtered.filter(c => (c.tool || 'ig-master-suite') === selectedTool);
            }
            
            // 2. Filter by search input query
            if (searchQuery !== '') {
                filtered = filtered.filter(c => {
                    const name = (c.name || '').toLowerCase();
                    const key = (c.key || '').toLowerCase();
                    const ip = (c.last_ip || '').toLowerCase();
                    const devId = (c.device_id || '').toLowerCase();
                    return name.includes(searchQuery) || key.includes(searchQuery) || ip.includes(searchQuery) || devId.includes(searchQuery);
                });
            }

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="empty-row-state">${clientsList.length === 0 ? "No licenses registered. Use key generator to create one." : "No clients match current filters/search criteria."}</td></tr>`;
                return;
            }

            let html = '';
            filtered.forEach(c => {
                const isActive = c.status === 'active';
                const statusBadgeClass = isActive ? 'bg-active' : 'bg-disabled';
                const statusLabel = isActive ? 'Active' : 'Suspended';
                
                const ipDisplay = c.last_ip 
                    ? `<span class="ip-cell">${c.last_ip}</span>` 
                    : `<span class="ip-none">Not checked in</span>`;
                
                const deviceDisplay = c.device_id
                    ? `<code style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #a5b4fc;">${c.device_id.slice(0, 15)}...</code>`
                    : `<span class="ip-none">No machine linked</span>`;
                
                const shortKey = c.key.substring(0, 14) + '...';
                const toolName = c.tool || 'ig-master-suite';
                
                const resetDeviceBtn = c.device_id
                    ? `<button class="btn-action-sm btn-sm-delete" style="background: rgba(99, 102, 241, 0.08); border-color: rgba(99, 102, 241, 0.15); color: #a5b4fc;" onclick="resetDeviceLock('${c.key}')" title="Reset device link to transfer key">🔓 Reset Link</button>`
                    : '';
                
                html += `<tr>
                    <td>
                        <div class="client-name-cell">${c.name}</div>
                        <div style="font-size: 11px; color: var(--primary); margin-top: 4px; font-weight: 500;">${toolName}</div>
                    </td>
                    <td>
                        <div class="client-key-code">
                            <span>${shortKey}</span>
                            <button class="btn-copy-table" onclick="copyTextDirectly('${c.key}')" title="Copy Full Key">📋</button>
                        </div>
                    </td>
                    <td class="expiry-cell">${c.expiry}</td>
                    <td>
                        <div>${deviceDisplay}</div>
                        <div style="margin-top: 4px;">${ipDisplay}</div>
                    </td>
                    <td>
                        <span class="badge-status ${statusBadgeClass}">
                            <span class="status-dot-mini"></span>
                            <span>${statusLabel}</span>
                        </span>
                    </td>
                    <td>
                        <div class="actions-group">
                            <button class="btn-action-sm ${isActive ? 'btn-sm-toggle-off' : 'btn-sm-toggle-on'}" onclick="toggleStatus('${c.key}')">
                                ${isActive ? '🛑 Suspend' : '✅ Activate'}
                            </button>
                            ${resetDeviceBtn}
                            <button class="btn-action-sm btn-sm-delete" onclick="deleteClient('${c.key}')" title="Delete Permanent">
                                🗑️ Delete
                            </button>
                        </div>
                    </td>
                </tr>`;
            });
            tbody.innerHTML = html;
        }

        async function loadClients() {
            const res = await fetchAPI('/api/clients');
            if (res.status === 'ok') {
                clientsList = res.clients || [];
                
                // Dynamically populate the filter dropdown with unique tool names
                const filterToolSelect = document.getElementById('sel-filter-tool');
                const currentSelected = filterToolSelect.value;
                
                filterToolSelect.innerHTML = `
                    <option value="all">All Applications</option>
                    <option value="ig-master-suite">IG Master Suite</option>
                    <option value="whatsapp-bulk-sender">Dreamcrest WhatsApp Sender</option>
                `;
                
                const uniqueTools = [...new Set(clientsList.map(c => c.tool).filter(Boolean))];
                uniqueTools.forEach(tool => {
                    if (tool !== 'ig-master-suite' && tool !== 'whatsapp-bulk-sender') {
                        const opt = document.createElement('option');
                        opt.value = tool;
                        opt.textContent = tool;
                        filterToolSelect.appendChild(opt);
                    }
                });
                
                filterToolSelect.value = currentSelected;
                if (!filterToolSelect.value) {
                    filterToolSelect.value = 'all';
                }

                updateKPIs();
                renderTable();
            }
        }

        window.onload = function() {
            loadClients();
            // Poll for fresh client registrations or IP ping updates every 15 seconds (cloud-friendly)
            setInterval(loadClients, 15000);
        };
    </script>
</body>
</html>
"""

# ── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return HTML_TEMPLATE

@app.route('/logo.png')
def logo():
    # Attempt to locate and serve the local logo.png
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(base_dir, "logo.png")):
        return send_from_directory(base_dir, "logo.png")
        
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        if os.path.exists(os.path.join(exe_dir, "logo.png")):
            return send_from_directory(exe_dir, "logo.png")
            
    return jsonify({"error": "Logo file not found"}), 404

@app.route('/api/clients')
def api_clients():
    db = load_db()
    return jsonify({"status": "ok", "clients": db["clients"]})

@app.route('/api/generate_key', methods=['POST'])
def api_generate_key():
    data = request.json or {}
    name = data.get("name", "Unknown Client").strip()
    if not name:
        name = "Unknown Client"
    days = data.get("days", 30)
    count = int(data.get("count", 1))
    if count < 1:
        count = 1
    
    tool = "all" # Force universal key target for all new license keys
    
    db = load_db()
    generated_keys = []
    
    for i in range(count):
        client_name = f"{name} #{i+1}" if count > 1 else name
        key_str, expiry_str = generate_key_string(days, tool)
        
        db["clients"].append({
            "name": client_name,
            "key": key_str,
            "expiry": expiry_str,
            "status": "active",
            "last_ip": None,
            "device_id": None,
            "tool": tool,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        generated_keys.append(key_str)
        
    save_db(db)
    
    return jsonify({
        "status": "ok",
        "key": generated_keys[0],
        "keys": generated_keys
    })

@app.route('/api/toggle_status', methods=['POST'])
def api_toggle_status():
    data = request.json or {}
    key = data.get("key")
    db = load_db()
    for c in db["clients"]:
        if c["key"] == key:
            c["status"] = "disabled" if c["status"] == "active" else "active"
            break
    save_db(db)
    return jsonify({"status": "ok"})

@app.route('/api/delete_client', methods=['POST'])
def api_delete_client():
    data = request.json or {}
    key = data.get("key")
    db = load_db()
    db["clients"] = [c for c in db["clients"] if c["key"] != key]
    save_db(db)
    return jsonify({"status": "ok"})

@app.route('/api/reset_device', methods=['POST'])
def api_reset_device():
    data = request.json or {}
    key = data.get("key")
    db = load_db()
    for c in db["clients"]:
        if c["key"] == key:
            c["device_id"] = None
            break
    save_db(db)
    return jsonify({"status": "ok"})

# ── NODE.JS APP COMPATIBILITY ENDPOINTS ──

@app.route('/api/license/activate', methods=['POST'])
def api_license_activate():
    data = request.json or {}
    key = data.get("key", "").strip()
    device_id = data.get("deviceId", "").strip()
    tool = data.get("tool", "dreamcrest-whatsapp-sender").strip().lower()

    if not key or not device_id:
        return jsonify({"error": "Missing key or deviceId"}), 400

    # Validate crypto signature of the license string
    is_valid, expiry_str = check_key_signature(key, tool)
    if not is_valid:
        return jsonify({"error": "Invalid key cryptographic signature or tool mismatch."}), 400

    db = load_db()
    found_client = None
    for c in db["clients"]:
        if c["key"] == key:
            found_client = c
            break

    if not found_client:
        return jsonify({"error": "License key not registered on admin console."}), 404

    # Bind device or verify binding (robust check to prevent false "already activated" triggers)
    current_device = found_client.get("device_id")
    if current_device and current_device not in (None, "", "None", "null") and current_device != device_id:
        return jsonify({"error": "This license key is already activated on another machine."}), 400

    if found_client["status"] == "disabled":
        return jsonify({"error": "This license has been suspended by the administrator."}), 403

    # Check expiration date
    try:
        exp_date = datetime.strptime(found_client["expiry"], "%Y-%m-%d").date()
        if datetime.now().date() > exp_date:
            return jsonify({"error": "This license key has expired."}), 400
    except Exception:
        pass

    # Save activation bindings
    found_client["device_id"] = device_id
    found_client["last_ip"] = request.remote_addr
    found_client["tool"] = found_client.get("tool", tool)  # Backfill tool if missing
    save_db(db)

    # Format expiry as ISO 8601 string
    try:
        exp_dt = datetime.strptime(found_client["expiry"], "%Y-%m-%d")
        iso_expiry = exp_dt.isoformat() + "Z"
    except Exception:
        iso_expiry = datetime.now().isoformat() + "Z"

    return jsonify({"success": True, "expiresAt": iso_expiry})

@app.route('/api/license/validate', methods=['POST'])
def api_license_validate():
    data = request.json or {}
    key = data.get("key", "").strip()
    device_id = data.get("deviceId", "").strip()
    tool = data.get("tool", "dreamcrest-whatsapp-sender").strip().lower()

    if not key or not device_id:
        return jsonify({"error": "Missing key or deviceId"}), 400

    db = load_db()
    found_client = None
    for c in db["clients"]:
        if c["key"] == key:
            found_client = c
            break

    if not found_client:
        return jsonify({"error": "License key not found."}), 404

    if found_client["status"] == "disabled":
        return jsonify({"error": "License key suspended."}), 403

    # Check device binding (robust check)
    current_device = found_client.get("device_id")
    if current_device and current_device not in (None, "", "None", "null") and current_device != device_id:
        return jsonify({"error": "Invalid hardware binding."}), 400

    # Check expiration date
    try:
        exp_date = datetime.strptime(found_client["expiry"], "%Y-%m-%d").date()
        if datetime.now().date() > exp_date:
            return jsonify({"error": "License key has expired."}), 400
    except Exception:
        pass

    # Update IP tracker
    found_client["last_ip"] = request.remote_addr
    save_db(db)

    try:
        exp_dt = datetime.strptime(found_client["expiry"], "%Y-%m-%d")
        iso_expiry = exp_dt.isoformat() + "Z"
    except Exception:
        iso_expiry = datetime.now().isoformat() + "Z"

    return jsonify({"success": True, "expiresAt": iso_expiry})

# ── LEGACY P2P CLIENT VERIFICATION ENDPOINT ──
@app.route('/api/verify_client', methods=['POST'])
def api_verify_client():
    data = request.json or {}
    client_key = data.get("license_key", "").strip()
    tool = data.get("tool", "ig-master-suite").strip().lower()
    client_ip = request.remote_addr

    # Validate crypto signature of the license string
    is_valid, _ = check_key_signature(client_key, tool)
    if not is_valid:
        return jsonify({"status": "disabled", "error": "Invalid key cryptographic signature or tool mismatch."}), 403

    db = load_db()
    found_client = None
    
    for c in db["clients"]:
        if c["key"] == client_key:
            found_client = c
            # Dynamic connection tracking: update last seen IP
            c["last_ip"] = client_ip
            c["tool"] = c.get("tool", tool)  # Backfill tool target if missing
            break
            
    if not found_client:
        return jsonify({"status": "disabled", "error": "License key not registered on admin console."}), 403

    save_db(db)

    if found_client["status"] == "disabled":
        return jsonify({"status": "disabled", "error": "This machine has been suspended by the administrator."}), 403

    # Extra: check date expiry again locally to prevent bypass
    try:
        expiry_date = datetime.strptime(found_client["expiry"], "%Y-%m-%d").date()
        if datetime.now().date() > expiry_date:
            return jsonify({"status": "disabled", "error": f"This license expired on {found_client['expiry']}."}), 403
    except Exception:
        pass

    return jsonify({"status": "active", "message": "Access authorized."})

# ── HEALTH CHECK FOR RENDER ──────────────────────────────────────────────────
@app.route('/health')
def health_check():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

# ── SERVER BOOTSTRAP ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8777))
    
    # Only auto-open browser when running locally (not on Render/cloud)
    if not IS_CLOUD:
        def auto_open():
            time.sleep(1.5)
            webbrowser.open(f"http://127.0.0.1:{port}")
        threading.Thread(target=auto_open, daemon=True).start()
    
    print("=" * 70)
    print("=== DREAMCREST - UNIVERSAL CONTROL CONSOLE ===")
    print("=" * 70)
    print("P2P Verification Server successfully started.")
    if IS_CLOUD:
        print(f"Cloud mode active. Listening on port {port}")
    else:
        print(f"Local Admin URL: http://127.0.0.1:{port}")
    print("Status database  : " + ("PostgreSQL (cloud)" if IS_CLOUD else DB_PATH))
    print("Keep this server window open for client verifications.")
    print("=" * 70)
    
    # Run listening on 0.0.0.0 so clients on external networks can reach this machine
    app.run(host="0.0.0.0", port=port, debug=False)
