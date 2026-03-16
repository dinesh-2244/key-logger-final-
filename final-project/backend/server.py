from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta, timezone
from functools import wraps
import os, logging, hashlib, json, random, csv, io

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
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
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
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
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
agent_sid = None  # Track the actual agent's session ID

@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    global agent_connected, agent_sid
    # Only mark agent as disconnected if the actual agent disconnected,
    # not when a dashboard browser tab disconnects
    if request.sid == agent_sid:
        agent_connected = False
        agent_sid = None
        logger.info(f"Threat agent disconnected: {request.sid}")
        emit('agent_status', {'connected': False}, broadcast=True)
    else:
        logger.info(f"Dashboard client disconnected: {request.sid}")

@socketio.on('agent_hello')
def handle_agent_hello(data):
    global agent_connected, agent_sid
    agent_connected = True
    agent_sid = request.sid
    logger.info(f"Threat agent connected (sid={request.sid}).")
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
        # Check if daily limit already exceeded before saving
        rule = ScreenTimeRule.query.first()
        limit_active = rule and rule.is_active
        max_seconds = (rule.max_daily_minutes * 60) if rule else float('inf')
        current_total = get_today_screen_time() if limit_active else 0

        for act in activities:
            # Use category from agent (Smart Filtering), fallback to Neutral
            category_name = act.get('category', 'Neutral')
            duration = max(0, int(act.get('duration', 0) or 0))

            # Cap duration so daily total never exceeds the limit
            if limit_active and current_total + duration > max_seconds:
                duration = max(0, max_seconds - current_total)
                if duration == 0:
                    continue  # Skip - limit already reached

            app_name = act.get('app_name', 'Unknown')
            window_title = act.get('window_title', '')

            # Merge with the most recent log ONLY if it's the same app+window
            # (i.e., user is still on the same page/app since the last poll).
            # This avoids creating a new row every 5s while still creating
            # a fresh row when the user switches to a different app or page.
            latest = ActivityLog.query.order_by(ActivityLog.id.desc()).first()

            if latest and latest.app_name == app_name and latest.window_title == window_title:
                latest.duration += duration
            else:
                log = ActivityLog(
                    timestamp=datetime.now(timezone.utc),
                    app_name=app_name,
                    window_title=window_title,
                    category=category_name,
                    duration=duration
                )
                db.session.add(log)

            current_total += duration
            saved_count += 1

        db.session.commit()

        # Check screen time limits
        check_screen_time_limits()
        
        emit('dashboard_update', {'message': 'New telemetry applied', 'count': saved_count}, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error handling live stream: {e}")

def get_today_screen_time():
    """Get total screen time used today in seconds."""
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    total = db.session.query(db.func.sum(ActivityLog.duration)).filter(
        ActivityLog.timestamp >= today_start
    ).scalar() or 0
    return total

def check_screen_time_limits():
    """Check if daily screen time exceeds the set limit and enforce it."""
    rule = ScreenTimeRule.query.first()
    if not rule or not rule.is_active:
        return

    total = get_today_screen_time()
    total_minutes = total / 60
    max_minutes = rule.max_daily_minutes

    if total_minutes >= max_minutes:
        logger.warning(f"Screen time limit reached: {total_minutes:.0f}/{max_minutes} minutes")
        socketio.emit('enforce_limit', {
            'reason': 'daily_limit_exceeded',
            'used_minutes': int(total_minutes),
            'max_minutes': max_minutes,
            'action': 'block'  # Tell agent to actively block
        }, namespace='/')
    elif total_minutes >= max_minutes * 0.9:
        # Warn at 90% usage
        socketio.emit('enforce_limit', {
            'reason': 'approaching_limit',
            'used_minutes': int(total_minutes),
            'max_minutes': max_minutes,
            'action': 'warn'
        }, namespace='/')

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
        session['login_time'] = datetime.now(timezone.utc).isoformat()
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
        day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
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
    try:
        rule.filter_intensity = int(data.get('filter_intensity', 5))
    except (ValueError, TypeError):
        rule.filter_intensity = 5
    rule.is_active = data.get('is_active', True) # Default from diff
    rule.updated_at = datetime.now(timezone.utc)
    
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
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
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

# --- Password Change ---

@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    global DEFAULT_PASSWORD_HASH
    data = request.get_json() or {}
    current = data.get('current_password', '')
    new_pw = data.get('new_password', '')

    if not new_pw or len(new_pw) < 6:
        return jsonify({"status": "error", "message": "New password must be at least 6 characters"}), 400

    current_hash = hashlib.sha256(current.encode()).hexdigest()
    if current_hash != DEFAULT_PASSWORD_HASH:
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 401

    DEFAULT_PASSWORD_HASH = hashlib.sha256(new_pw.encode()).hexdigest()
    logger.info("Password changed successfully.")
    return jsonify({"status": "ok", "message": "Password changed successfully"})

# --- CSV Export ---

@app.route("/api/reports/export", methods=["GET"])
@login_required
def export_csv():
    """Export activity logs and threat data as CSV."""
    report_type = request.args.get('type', 'activity')

    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == 'threats':
        writer.writerow(['Timestamp', 'Severity', 'Keyword', 'Application', 'Context'])
        threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
        for t in threats:
            writer.writerow([
                t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                t.severity, t.keyword, t.app_name, t.full_buffer or ''
            ])
        filename = f"guardian_threats_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    else:
        writer.writerow(['Timestamp', 'Application', 'Window Title', 'Category', 'Duration (seconds)'])
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.app_name, log.window_title or '', log.category or 'Neutral', log.duration
            ])
        filename = f"guardian_activity_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

# --- Demo Simulation ---

@app.route("/api/demo/simulate", methods=["POST"])
@login_required
def demo_simulate():
    """Inject realistic sample data for project demonstration."""
    try:
        now = datetime.now(timezone.utc)

        # Sample apps with categories
        sample_apps = [
            ("Google Chrome", "Khan Academy - Courses", "Educational", 300),
            ("Google Chrome", "YouTube - Math Tutorial (https://youtube.com/watch?v=abc)", "Entertainment", 180),
            ("Visual Studio Code", "project/main.py - VSCode", "Educational", 600),
            ("Google Chrome", "Wikipedia - Python Programming (https://en.wikipedia.org/wiki/Python)", "Educational", 240),
            ("Discord", "General - Study Group", "Social Media", 120),
            ("Spotify", "Focus Playlist", "Entertainment", 90),
            ("Google Chrome", "Coursera - Machine Learning (https://coursera.org/learn/ml)", "Educational", 420),
            ("Google Chrome", "Reddit - r/programming (https://reddit.com/r/programming)", "Social Media", 150),
            ("Terminal", "pip install numpy", "Educational", 60),
            ("Google Chrome", "Stack Overflow - Python Error (https://stackoverflow.com/questions/123)", "Educational", 200),
            ("Minecraft", "Minecraft Java Edition", "Entertainment", 300),
            ("Google Chrome", "Netflix - Documentary (https://netflix.com/watch/456)", "Entertainment", 360),
            ("Microsoft Word", "Final Year Report.docx", "Educational", 500),
            ("Google Chrome", "GitHub - Repository (https://github.com/user/project)", "Educational", 280),
            ("Brave Browser", "Twitter - Feed (https://twitter.com/home)", "Social Media", 100),
        ]

        # Generate today's data (spread across last 6 hours)
        for i, (app, title, cat, dur) in enumerate(sample_apps):
            minutes_ago = random.randint(10, 360)
            log = ActivityLog(
                timestamp=now - timedelta(minutes=minutes_ago),
                app_name=app,
                window_title=title,
                category=cat,
                duration=dur + random.randint(-30, 30)
            )
            db.session.add(log)

        # Generate last 7 days of historical data for weekly charts
        for days_ago in range(1, 7):
            day = now - timedelta(days=days_ago)
            # Educational apps
            for _ in range(random.randint(3, 6)):
                db.session.add(ActivityLog(
                    timestamp=day.replace(hour=random.randint(8, 18), minute=random.randint(0, 59)),
                    app_name=random.choice(["Google Chrome", "Visual Studio Code", "Microsoft Word", "Terminal"]),
                    window_title=random.choice(["Khan Academy", "Coursera", "Research Paper", "Code Editor", "Stack Overflow"]),
                    category="Educational",
                    duration=random.randint(120, 600)
                ))
            # Entertainment apps
            for _ in range(random.randint(2, 4)):
                db.session.add(ActivityLog(
                    timestamp=day.replace(hour=random.randint(15, 21), minute=random.randint(0, 59)),
                    app_name=random.choice(["YouTube", "Spotify", "Minecraft", "Netflix"]),
                    window_title=random.choice(["Gaming Session", "Music Playlist", "Movie Time", "YouTube Video"]),
                    category="Entertainment",
                    duration=random.randint(60, 400)
                ))
            # Neutral apps
            for _ in range(random.randint(1, 3)):
                db.session.add(ActivityLog(
                    timestamp=day.replace(hour=random.randint(9, 20), minute=random.randint(0, 59)),
                    app_name=random.choice(["File Explorer", "Settings", "Calculator", "Notepad"]),
                    window_title="Main Window",
                    category="Neutral",
                    duration=random.randint(30, 120)
                ))

        db.session.commit()

        # Broadcast update to dashboard
        socketio.emit('dashboard_update', {'message': 'Demo data loaded', 'count': len(sample_apps)}, namespace='/')

        logger.info(f"Demo data injected: {len(sample_apps)} today + 7 days history")
        return jsonify({"status": "ok", "message": f"Injected {len(sample_apps)} activity records + 7 days of history"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Demo simulation error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/demo/threat", methods=["POST"])
@login_required
def demo_threat():
    """Simulate a live threat alert for demonstration."""
    try:
        keywords = ["hack", "bypass", "exploit", "password", "credit card"]
        keyword = random.choice(keywords)
        apps = ["Google Chrome", "Terminal", "Discord", "Notepad"]
        app_name = random.choice(apps)
        buffers = {
            "hack": "how to hack wifi password",
            "bypass": "bypass school firewall vpn",
            "exploit": "exploit vulnerability tutorial",
            "password": "steal password from browser",
            "credit card": "find credit card numbers online"
        }

        threat = ThreatLog(
            keyword=keyword,
            app_name=app_name,
            full_buffer=buffers.get(keyword, keyword),
            severity="high" if keyword in ['exploit', 'hack'] else "medium"
        )
        db.session.add(threat)
        db.session.commit()

        # Broadcast live threat to dashboard
        socketio.emit('live_threat', {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'keyword': keyword,
            'app_name': app_name,
            'full_buffer': buffers.get(keyword, keyword),
            'category': 'Threat'
        }, namespace='/')

        return jsonify({"status": "ok", "message": f"Threat simulated: '{keyword}' in {app_name}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/demo/keystroke", methods=["POST"])
@login_required
def demo_keystroke():
    """Simulate live keystrokes for demonstration."""
    sentences = [
        "Hello, I am working on my final year project for cybersecurity class.",
        "This parental monitoring tool tracks application usage and detects threats.",
        "The system uses WebSocket for real-time communication between agent and server.",
        "Let me search for some educational content on Khan Academy.",
        "import numpy as np\ndata = np.array([1, 2, 3])\nprint(data.mean())",
    ]
    sentence = random.choice(sentences)
    app_name = random.choice(["Google Chrome", "Visual Studio Code", "Terminal", "Microsoft Word"])

    for char in sentence:
        socketio.emit('live_keylog', {
            'char': char,
            'app_name': app_name
        }, namespace='/')

    return jsonify({"status": "ok", "message": f"Simulated {len(sentence)} keystrokes in {app_name}"})

@app.route("/api/demo/clear", methods=["POST"])
@login_required
def demo_clear():
    """Clear all demo/activity data."""
    try:
        ActivityLog.query.delete()
        ThreatLog.query.delete()
        db.session.commit()
        socketio.emit('dashboard_update', {'message': 'Data cleared'}, namespace='/')
        return jsonify({"status": "ok", "message": "All activity and threat data cleared"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

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
    socketio.run(app, host="0.0.0.0", port=2000, debug=False)