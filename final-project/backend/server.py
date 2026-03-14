from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
from functools import wraps
import os, logging, hashlib, json

# --- App Setup ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'guardian-lens-secret-2026')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Database Setup
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'telemetry.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'timeout': 20},
    'pool_pre_ping': True,
}

db = SQLAlchemy(app)

# Default parent password (sha256 hash of "parent123")
DEFAULT_PASSWORD_HASH = hashlib.sha256("parent123".encode()).hexdigest()

# --- Database Models ---

class AppCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    multiplier = db.Column(db.Float, default=1.0)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    duration = db.Column(db.Integer, nullable=False) # Renamed from duration_seconds
    app_name = db.Column(db.String(100), nullable=False)
    window_title = db.Column(db.String(500), nullable=True)
    category = db.Column(db.String(50), nullable=True) # Changed from category_id to category string

class ScreenTimeRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    max_daily_minutes = db.Column(db.Integer, default=120)
    active_hours_start = db.Column(db.String(5), default="08:00")  # HH:MM
    active_hours_end = db.Column(db.String(5), default="21:00")
    blocked_apps = db.Column(db.String(500), default="[]")  # JSON list, changed type to String(500)
    filter_intensity = db.Column(db.Integer, default=5) # New field
    is_active = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    keyword = db.Column(db.String(100), nullable=False)
    app_name = db.Column(db.String(100), nullable=False)
    full_buffer = db.Column(db.String(500), nullable=True)
    severity = db.Column(db.String(20), default="medium")  # low, medium, high

# --- Auth Decorator ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# --- WebSocket Real-Time Events ---

agent_connected = False

@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('agent_hello')
def handle_agent_hello(data):
    global agent_connected
    agent_connected = True
    logger.info("Threat agent connected.")
    emit('agent_status', {'connected': True}, broadcast=True)
    # Send current rules to agent
    rule = ScreenTimeRule.query.first()
    if rule:
        emit('rules_update', {
            'max_daily_minutes': rule.max_daily_minutes,
            'active_hours_start': rule.active_hours_start,
            'active_hours_end': rule.active_hours_end,
            'blocked_apps': json.loads(rule.blocked_apps or '[]'),
            'filter_intensity': rule.filter_intensity, # Added filter_intensity
            'is_active': rule.is_active
        }, room=request.sid) # Added room=request.sid to target the connecting agent

@socketio.on('telemetry_stream')
def handle_telemetry_stream(data):
    """Receive live telemetry from the edge agent and save/broadcast."""
    activities = data.get("activities", [])
    saved_count = 0
    
    try:
        for act in activities:
            # Use category from agent (Smart Filtering), fallback to Neutral
            category_name = act.get('category', 'Neutral')

            log = ActivityLog(
                timestamp=datetime.now(),
                app_name=act.get('app_name', 'Unknown'),
                window_title=act.get('window_title', ''),
                category=category_name,
                duration=int(act.get('duration', 0))
            )
            db.session.add(log)
            saved_count += 1
            
        db.session.commit()
        
        # Check screen time limits
        check_screen_time_limits()
        
        emit('dashboard_update', {'message': 'New telemetry applied', 'count': saved_count}, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error handling live stream: {e}")

def check_screen_time_limits():
    """Check if daily screen time exceeds the set limit and notify agent."""
    rule = ScreenTimeRule.query.first()
    if not rule or not rule.is_active:
        return
    
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    total = db.session.query(db.func.sum(ActivityLog.duration)).filter( # Changed to ActivityLog.duration
        ActivityLog.timestamp >= today_start
    ).scalar() or 0
    
    total_minutes = total / 60
    if total_minutes >= rule.max_daily_minutes:
        logger.warning(f"Screen time limit reached: {total_minutes:.0f}/{rule.max_daily_minutes} minutes")
        socketio.emit('enforce_limit', {
            'reason': 'daily_limit_exceeded',
            'used_minutes': int(total_minutes),
            'max_minutes': rule.max_daily_minutes
        })

@socketio.on('threat_alert')
def handle_threat_alert(data):
    """Receive threat alerts, persist to DB, and broadcast to dashboard."""
    logger.warning(f"THREAT ALERT: {data.get('keyword')} in {data.get('app_name')}")
    
    try:
        severity = "high" if data.get('keyword', '') in ['suicide', 'exploit', 'hack'] else "medium"
        if data.get('keyword', '') in ['porn', 'pornhub', 'xvideos', 'onlyfans']:
            severity = "high"
        
        threat = ThreatLog(
            keyword=data.get('keyword', ''),
            app_name=data.get('app_name', ''),
            full_buffer=data.get('full_buffer', '')[:500],
            severity=severity
        )
        db.session.add(threat)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving threat: {e}")
    
    emit('live_threat', data, broadcast=True)

@socketio.on('raw_keystroke')
def handle_raw_keystroke(data):
    emit('live_keylog', data, broadcast=True)

# --- Auth Routes ---

@app.route("/login")
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    password = data.get('password', '')
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if pw_hash == DEFAULT_PASSWORD_HASH:
        session['logged_in'] = True
        session['login_time'] = datetime.now().isoformat()
        logger.info("Parent logged in successfully.")
        return jsonify({"status": "ok"})
    
    logger.warning("Failed login attempt.")
    return jsonify({"status": "error", "message": "Invalid password"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "ok"})

# --- API Endpoints ---

@app.route("/api/analytics/daily", methods=["GET"])
@login_required
def get_daily_analytics():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    # The diff provided a new structure for the return value.
    logs_data = [{
        "timestamp": log.timestamp.isoformat(),
        "app_name": log.app_name,
        "window_title": log.window_title,
        "category": log.category, # Use category string directly
        "duration": log.duration # Use new duration field
    } for log in logs]
    return jsonify({"status": "success", "data": logs_data}), 200

@app.route("/api/reports/weekly", methods=["GET"])
@login_required
def get_weekly_report():
    """Return 7-day usage breakdown by category."""
    days = []
    for i in range(6, -1, -1):
        day = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
        next_day = day + timedelta(days=1)
        
        edu = db.session.query(db.func.sum(ActivityLog.duration)).filter(
            ActivityLog.timestamp >= day, ActivityLog.timestamp < next_day,
            ActivityLog.category == "Educational"
        ).scalar() or 0
        
        ent = db.session.query(db.func.sum(ActivityLog.duration)).filter(
            ActivityLog.timestamp >= day, ActivityLog.timestamp < next_day,
            ActivityLog.category == "Entertainment"
        ).scalar() or 0
        
        neutral = db.session.query(db.func.sum(ActivityLog.duration)).filter(
            ActivityLog.timestamp >= day, ActivityLog.timestamp < next_day,
            ActivityLog.category == "Neutral"
        ).scalar() or 0

        days.append({
            "date": day.strftime("%a %d"),
            "educational": round(float(edu) / 60, 1),
            "entertainment": round(float(ent) / 60, 1),
            "neutral": round(float(neutral) / 60, 1)
        })
    
    return jsonify({"data": days})


@app.route("/api/reports/threats", methods=["GET"])
@login_required
def get_threat_history():
    threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(50).all()
    return jsonify({"data": [{
        "id": t.id,
        "timestamp": t.timestamp.isoformat(),
        "keyword": t.keyword,
        "app_name": t.app_name,
        "full_buffer": t.full_buffer,
        "severity": t.severity
    } for t in threats]})

@app.route("/api/rules", methods=["GET"])
@login_required
def get_rules():
    rule = ScreenTimeRule.query.first()
    if not rule:
        return jsonify({"data": None})
    return jsonify({"data": {
        "max_daily_minutes": rule.max_daily_minutes,
        "active_hours_start": rule.active_hours_start,
        "active_hours_end": rule.active_hours_end,
        "blocked_apps": json.loads(rule.blocked_apps or '[]'),
        "filter_intensity": rule.filter_intensity, # Added filter_intensity
        "is_active": rule.is_active
    }})

@app.route("/api/rules", methods=["POST"])
@login_required
def save_rules():
    data = request.get_json() or {}
    rule = ScreenTimeRule.query.first()
    if not rule:
        rule = ScreenTimeRule()
        db.session.add(rule)
    
    # The diff provided a new structure for rule assignment.
    # Integrating the new fields and structure while maintaining the original flow.
    rule.max_daily_minutes = data.get('max_daily_minutes', rule.max_daily_minutes)
    rule.active_hours_start = data.get('active_hours_start', '08:00') # Default from diff
    rule.active_hours_end = data.get('active_hours_end', '21:00') # Default from diff
    rule.blocked_apps = json.dumps(data.get('blocked_apps', []))
    rule.filter_intensity = int(data.get('filter_intensity', 5)) # Added filter_intensity
    rule.is_active = data.get('is_active', True) # Default from diff
    rule.updated_at = datetime.now()
    
    db.session.commit()
    logger.info(f"Rules updated: {data}")
    
    # Push rules to connected agent
    socketio.emit('rules_update', {
        'max_daily_minutes': rule.max_daily_minutes,
        'active_hours_start': rule.active_hours_start,
        'active_hours_end': rule.active_hours_end,
        'blocked_apps': json.loads(rule.blocked_apps),
        'filter_intensity': rule.filter_intensity, # Added filter_intensity
        'is_active': rule.is_active
    }, namespace='/') # emit to all connected clients
    return jsonify({"status": "success", "message": "Rules updated and pushed to agent"}), 200 # Added return statement as per diff

@app.route("/api/status", methods=["GET"])
@login_required
def get_status():
    """Return agent connection status and today's screen time."""
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    total = db.session.query(db.func.sum(ActivityLog.duration)).filter(
        ActivityLog.timestamp >= today_start
    ).scalar() or 0
    
    rule = ScreenTimeRule.query.first()
    return jsonify({
        "agent_connected": agent_connected,
        "total_screen_time_minutes": round(total / 60, 1),
        "max_daily_minutes": rule.max_daily_minutes if rule else 120,
        "limit_active": rule.is_active if rule else False
    })

# --- Frontend Routes ---

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

# --- Initialization ---

def init_db():
    with app.app_context():
        # Create tables FIRST (must exist before any queries)
        db.create_all()
        
        # Set SQLite pragmas for performance
        from sqlalchemy import text
        try:
            db.session.execute(text("PRAGMA journal_mode=WAL"))
            db.session.execute(text("PRAGMA busy_timeout=5000"))
            db.session.commit()
        except Exception as e:
            logger.warning(f"PRAGMA setup failed (non-critical): {e}")
            db.session.rollback()
        
        # Seed default categories
        if not AppCategory.query.first():
            db.session.add(AppCategory(name="Educational", multiplier=2.0))
            db.session.add(AppCategory(name="Entertainment", multiplier=-1.0))
            db.session.add(AppCategory(name="Neutral", multiplier=0.0))
            db.session.commit()
            logger.info("Database initialized with default categories.")
        
        # Seed default screen time rule
        if not ScreenTimeRule.query.first():
            rule = ScreenTimeRule(
                max_daily_minutes=120,
                active_hours_start="08:00",
                active_hours_end="21:00",
                blocked_apps="[]",
                filter_intensity=5,
                is_active=True
            )
            db.session.add(rule)
            db.session.commit()
            logger.info("Default screen time rules created.")


if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=2000, debug=True)