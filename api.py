import copy, json, os, sqlite3
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit
from flask import Flask, jsonify, request
from flask_cors import CORS
from service import model_info, scan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
CORS(app, resources={r"/*": {"origins": os.getenv("VIGIL_FRONTEND_ORIGIN", "http://localhost:5173")}})
DB_PATH = os.path.join(os.path.dirname(__file__), "vigil_history.sqlite3")

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, url TEXT NOT NULL, result TEXT NOT NULL)")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def err(code, message, status): return jsonify({"error": code, "message": message}), status

def _history_result(result):
    """Persist only a query/fragment-free URL; query strings may contain secrets."""
    stored = copy.deepcopy(result)
    parsed = urlsplit(result["normalized_url"])
    safe_authority = parsed.netloc.rsplit("@", 1)[-1]
    safe_url = urlunsplit((parsed.scheme, safe_authority, parsed.path, "", ""))
    stored["url"] = safe_url
    stored["normalized_url"] = safe_url
    return stored

@app.get("/")
def home(): return jsonify({"service": "VIGIL API", "status": "ok"})

@app.errorhandler(413)
def request_too_large(_error):
    return err("request_too_large", "The request body is too large.", 413)

@app.get("/health")
def health():
    try: info = model_info(); return jsonify({"status": "ok", "model_loaded": True, "model_version": info.get("model_version")})
    except Exception: return jsonify({"status": "degraded", "model_loaded": False, "model_version": None}), 503

@app.get("/model-info")
def model_info_route():
    try: return jsonify(model_info())
    except Exception: return err("model_unavailable", "The classification model is not available. Check the backend logs.", 503)

@app.post("/scan")
def scan_route():
    if not request.is_json: return err("invalid_json", "Request body must be JSON.", 400)
    data = request.get_json(silent=True)
    if data is None: return err("invalid_json", "Request body must contain valid JSON.", 400)
    if not isinstance(data, dict) or "url" not in data: return err("empty_url", "Enter a URL to scan.", 400)
    url = data["url"]
    if not isinstance(url, str) or not url.strip(): return err("empty_url", "Enter a URL to scan.", 400)
    try: result = scan(url)
    except ValueError as exc:
        code = str(exc); messages = {"empty_url": "Enter a URL to scan.", "invalid_url": "Enter a valid URL beginning with http:// or https://.", "unsupported_scheme": "Only http:// and https:// URLs are supported.", "url_too_long": "The URL is too long."}; return err(code if code in messages else "invalid_url", messages.get(code, messages["invalid_url"]), 413 if code == "url_too_long" else 400)
    except FileNotFoundError: return err("model_unavailable", "The classification model is not available. Check the backend logs.", 503)
    except RuntimeError as exc:
        if str(exc) == "model_unavailable": return err("model_unavailable", "The classification model is not available. Check the backend logs.", 503)
        return err("internal_error", "The scan could not be completed.", 500)
    except Exception: return err("internal_error", "The scan could not be completed.", 500)
    stored = _history_result(result)
    with db() as conn: conn.execute("INSERT INTO scans(scanned_at,url,result) VALUES (?,?,?)", (result["scanned_at"], stored["url"], json.dumps(stored)))
    return jsonify(result)

@app.get("/history")
def history():
    with db() as conn: rows = conn.execute("SELECT id, scanned_at, url, result FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([{**json.loads(row[3]), "id": row[0]} for row in rows])

@app.get("/history/<int:item_id>")
def history_item(item_id):
    with db() as conn: row = conn.execute("SELECT result FROM scans WHERE id=?", (item_id,)).fetchone()
    return (jsonify({**json.loads(row[0]), "id": item_id}) if row else err("not_found", "Scan history item was not found.", 404))

@app.delete("/history")
def clear_history():
    with db() as conn: conn.execute("DELETE FROM scans")
    return jsonify({"status": "cleared"})

if __name__ == "__main__": app.run(host="127.0.0.1", port=int(os.getenv("VIGIL_PORT", "5000")), debug=False)
