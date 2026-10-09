import copy, json, math, os, sqlite3, time
import uuid
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from service import model_info, scan

from legal_knowledge import get_legal_knowledge_storage
from scam_broadcast import get_scam_case_storage
from threat_intel import (
    StreamEvent,
    get_threat_broadcaster,
    get_threat_pipeline,
    get_threat_scheduler,
    get_threat_storage,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 65536  # Support slightly larger payloads for batch operations while staying bounded
CORS(app, resources={r"/*": {"origins": "*"}})
DB_PATH = os.path.join(os.path.dirname(__file__), "vigil_history.sqlite3")
API_INSTANCE_ID = str(uuid.uuid4())
DEBUG_DIAGNOSTICS = os.getenv("VIGIL_DEBUG", "").lower() in {"1", "true", "yes"}

# Initialize threat intel, scam broadcast, and legal knowledge subsystems
threat_storage = get_threat_storage()
threat_broadcaster = get_threat_broadcaster()
threat_pipeline = get_threat_pipeline()
threat_scheduler = get_threat_scheduler()
scam_storage = get_scam_case_storage()
legal_storage = get_legal_knowledge_storage()

# Automatically start ingestion scheduler daemon unless explicitly disabled in tests
if os.getenv("VIGIL_DISABLE_SCHEDULER", "").lower() not in {"1", "true", "yes"}:
    threat_scheduler.start(initial_sync=True)

def _backend_identity(endpoint):
    return {
        "api_endpoint": endpoint,
        "backend_pid": os.getpid(),
        "backend_instance_id": API_INSTANCE_ID,
    }

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, url TEXT NOT NULL, result TEXT NOT NULL)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC)")
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
    try:
        info = model_info()
        return jsonify({
            "status": "ok",
            "model_loaded": True,
            "model_version": info.get("model_version"),
            "model_fingerprint": info.get("model_fingerprint"),
            "backend": _backend_identity(request.base_url),
        })
    except Exception:
        return jsonify({"status": "degraded", "model_loaded": False, "model_version": None}), 503

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
    request_id = request.headers.get("X-Vigil-Request-Id")
    try:
        request_id = str(uuid.UUID(request_id)) if request_id else str(uuid.uuid4())
    except (ValueError, AttributeError):
        request_id = str(uuid.uuid4())
    try:
        result = scan(url, request_id=request_id, include_diagnostics=DEBUG_DIAGNOSTICS)
    except ValueError as exc:
        code = str(exc); messages = {"empty_url": "Enter a URL to scan.", "invalid_url": "Enter a valid URL beginning with http:// or https://.", "unsupported_scheme": "Only http:// and https:// URLs are supported.", "url_too_long": "The URL is too long."}; return err(code if code in messages else "invalid_url", messages.get(code, messages["invalid_url"]), 413 if code == "url_too_long" else 400)
    except FileNotFoundError: return err("model_unavailable", "The classification model is not available. Check the backend logs.", 503)
    except RuntimeError as exc:
        if str(exc) == "model_unavailable": return err("model_unavailable", "The classification model is not available. Check the backend logs.", 503)
        return err("internal_error", "The scan could not be completed.", 500)
    except Exception: return err("internal_error", "The scan could not be completed.", 500)
    result["backend"] = _backend_identity(request.base_url)
    if DEBUG_DIAGNOSTICS:
        app.logger.info(
            "vigil_scan %s",
            json.dumps({
                "request_id": request_id,
                "normalized_url": result["normalized_url"],
                "hostname": result["diagnostics"]["hostname"],
                **result["backend"],
                "model_version": result["model_version"],
                "model_fingerprint": result["model_fingerprint"],
                "raw_fold_probabilities": result["diagnostics"]["raw_fold_probabilities"],
                "calibrated_probability": result["model_probability"],
                "effective_probability": result["effective_probability"],
                "thresholds": result["thresholds"],
                "verdict": result["label"],
                "risk_score": result["risk_score"],
                "cache_hit": False,
            }, sort_keys=True),
        )
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

# ==========================================
# MODULE 1: GLOBAL SCAMWATCH LIVE (SSE & REST)
# ==========================================

@app.get("/threat-feed/stream")
def threat_feed_stream():
    """
    Live Server-Sent Events (SSE) feed.
    Streams new threat indicators, stats updates, and source health changes without page refresh.
    Supports Last-Event-ID for reconnection recovery.
    """
    client_id, q = threat_broadcaster.subscribe()

    last_event_id = request.headers.get("Last-Event-ID") or request.args.get("last_event_id")
    initial_events = []
    if last_event_id:
        try:
            parts = last_event_id.split("_")
            cursor_id = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else int(parts[0])
            missed = threat_storage.get_indicators_since(cursor_id, limit=50)
            for item in missed:
                initial_events.append(
                    StreamEvent(
                        event_id=f"evt_{item.id}_{int(time.time()*1000)}",
                        event_type="indicator.new",
                        indicator=item.to_dict(),
                        stats=None,
                        source_health=None,
                        source_timestamp=item.source_timestamp,
                        ingested_at=item.ingested_at,
                        persisted_at=item.ingested_at,
                        emitted_at=item.ingested_at,
                    )
                )
        except Exception:
            pass

    response = Response(
        threat_broadcaster.sse_event_generator(
            client_id=client_id,
            q=q,
            initial_events=initial_events,
        ),
        mimetype="text/event-stream",
    )
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response

@app.get("/threat-feed/indicators")
def threat_feed_indicators():
    """Paginated threat indicators query with filtering and search."""
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    source = request.args.get("source")
    category = request.args.get("category")
    status = request.args.get("status")
    search = request.args.get("q")

    indicators, total = threat_storage.query_indicators(
        page=page,
        limit=limit,
        source=source,
        category=category,
        status=status,
        search=search,
    )

    total_pages = math.ceil(total / limit) if total > 0 else 1
    return jsonify({
        "indicators": [ind.to_dict() for ind in indicators],
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
    })

@app.get("/threat-feed/stats")
def threat_feed_stats():
    """Return aggregated live feed statistics."""
    stats = threat_storage.get_feed_stats(active_stream_clients=threat_broadcaster.client_count)
    return jsonify(stats.to_dict())

@app.get("/threat-feed/sources")
def threat_feed_sources():
    """Return status and health metrics for all upstream threat providers."""
    for p in threat_scheduler.providers:
        threat_storage.save_source_status(p.get_source_status())
    statuses = threat_storage.get_all_source_statuses()
    return jsonify([s.to_dict() for s in statuses])

@app.post("/threat-feed/sync")
def threat_feed_sync():
    """Trigger on-demand sync of upstream threat intelligence feeds."""
    limit = request.args.get("limit", 150, type=int)
    results = threat_scheduler.trigger_all_sync(limit=limit)
    return jsonify({"status": "completed", "results": results})

@app.post("/threat-feed/test-inject")
def threat_feed_test_inject():
    """
    Test injection endpoint for automated testing and verifying real-time live feed updates.
    Broadcasts the newly injected threat indicator via SSE.
    """
    if not request.is_json:
        return err("invalid_json", "Request body must be JSON.", 400)
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not url or not isinstance(url, str):
        return err("missing_url", "URL is required for test indicator injection.", 400)

    source = data.get("source", "test_feed")
    indicator_type = data.get("indicator_type", "phishing_url")
    threat_type = data.get("threat_type", "synthetic_threat_test")
    tags = data.get("tags", ["test_injection", "live_stream_verification"])
    source_timestamp = data.get("source_timestamp")
    status = data.get("status", "active")

    indicator = threat_pipeline.inject_test_indicator(
        url=url,
        source=source,
        indicator_type=indicator_type,
        threat_type=threat_type,
        tags=tags,
        source_timestamp=source_timestamp,
        status=status,
    )
    return jsonify({"status": "injected", "indicator": indicator.to_dict()})

# ==========================================
# MODULE 2: CYBER SCAM CASE BROADCAST ROUTES
# ==========================================

@app.get("/scam-cases")
def list_scam_cases():
    """List verified cyber scam cases with filtering and search."""
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)
    scam_type = request.args.get("scam_type")
    status = request.args.get("status")
    severity = request.args.get("severity")
    search = request.args.get("q")

    cases, total = scam_storage.query_cases(
        page=page,
        limit=limit,
        scam_type=scam_type,
        status=status,
        severity=severity,
        search=search,
    )
    total_pages = math.ceil(total / limit) if total > 0 else 1
    return jsonify({
        "cases": [c.to_dict() for c in cases],
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
    })

@app.get("/scam-cases/<string:id_or_slug>")
def get_scam_case_detail(id_or_slug: str):
    """Get complete case study with attack chain, recovery steps, and legal references."""
    case = scam_storage.get_case(id_or_slug)
    if not case:
        return err("not_found", "Scam case broadcast was not found.", 404)
    return jsonify(case.to_dict())

@app.get("/scam-cases/stats")
def get_scam_stats_route():
    """Return summary statistics of documented scam cases."""
    return jsonify(scam_storage.get_scam_stats())

# ==========================================
# MODULE 3: INDIA DIGITAL RIGHTS & CYBER LAW ROUTES
# ==========================================

@app.get("/legal-knowledge/instruments")
def get_legal_instruments():
    """List legal instruments (Constitution, Acts, Rules, Regulations, Directions)."""
    category = request.args.get("category")
    search = request.args.get("q")
    instruments = legal_storage.get_all_instruments(category=category, search=search)
    return jsonify([inst.to_dict() for inst in instruments])

@app.get("/legal-knowledge/instruments/<string:inst_id>")
def get_legal_instrument_detail(inst_id: str):
    """Get single legal instrument with all provisions, citizen remedies, and official source URL."""
    inst = legal_storage.get_instrument(inst_id)
    if not inst:
        return err("not_found", "Legal instrument was not found.", 404)
    return jsonify(inst.to_dict())

@app.get("/legal-knowledge/scenarios")
def get_legal_scenarios():
    """List real-world cyber scenarios mapped to legal provisions and reporting steps."""
    search = request.args.get("q")
    scenarios = legal_storage.get_all_scenarios(search=search)
    return jsonify([sc.to_dict() for sc in scenarios])

@app.get("/legal-knowledge/scenarios/<string:sc_id>")
def get_legal_scenario_detail(sc_id: str):
    """Get single scenario guidance."""
    sc = legal_storage.get_scenario(sc_id)
    if not sc:
        return err("not_found", "Legal scenario was not found.", 404)
    return jsonify(sc.to_dict())

@app.get("/legal-knowledge/glossary")
def get_legal_glossary():
    """List search-enabled cyber legal glossary terms."""
    search = request.args.get("q")
    terms = legal_storage.get_glossary(search=search)
    return jsonify([t.to_dict() for t in terms])

@app.get("/legal-knowledge/guides")
def get_citizen_guides():
    """List practical citizen action guides."""
    category = request.args.get("category")
    guides = legal_storage.get_guides(category=category)
    return jsonify([g.to_dict() for g in guides])

@app.get("/legal-knowledge/search")
def search_legal_knowledge():
    """Cross-cutting search across instruments, scenarios, glossary, and guides."""
    query = request.args.get("q", "")
    return jsonify(legal_storage.search_all(query))

if __name__ == "__main__": app.run(host="127.0.0.1", port=int(os.getenv("VIGIL_PORT", "5000")), debug=False)
