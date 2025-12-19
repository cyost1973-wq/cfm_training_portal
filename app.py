import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from datetime import datetime
import os
from functools import wraps
import csv
from io import StringIO

from werkzeug.security import generate_password_hash, check_password_hash
import markdown

app = Flask(__name__)

# Secret key from environment (set this in Render)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")

# --- Paths ---
BASE_DIR = os.path.dirname(__file__)

# SQLite DB path
# NOTE: If you later add a Render Persistent Disk, set DATA_DIR=/path/to/mount and DB will live there.
DATA_DIR = os.getenv("DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "training.db")

# --- Required modules ---
MODULES = [
    ("M1", "Welcome & CFM Culture"),
    ("M2", "CFM General Safety Rules"),
    ("M3", "OSHA Bloodborne Pathogens & Sharps Safety"),
    ("M4", "Infection Prevention & Standard Precautions"),
    ("M5", "OSHA Hazard Communication (SDS, labeling)"),
    ("M6", "Emergency Preparedness (Fire, Weather, Codes)"),
    ("M7", "HIPAA Privacy Basics"),
    ("M8", "HIPAA Security Basics (Electronic PHI)"),
    ("M9", "Incident & Near-Miss Reporting"),
    ("M10", "Workplace Violence & Harassment Prevention"),
]

# -------------------------
# DB helpers
# -------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Employees / Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name  TEXT NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'staff'
        )
        """
    )

    # Progress table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            module_id   TEXT NOT NULL,
            best_score  INTEGER,
            status      TEXT NOT NULL DEFAULT 'not_started',
            date_completed TEXT,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
        """
    )

    # Quiz questions table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_id TEXT NOT NULL,
            question  TEXT NOT NULL,
            answer_a  TEXT NOT NULL,
            answer_b  TEXT NOT NULL,
            answer_c  TEXT NOT NULL,
            answer_d  TEXT NOT NULL,
            correct_option TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    # Quiz attempts table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            module_id TEXT NOT NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            passed INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
        """
    )

    # Unique index so seeding/import can be safely repeated
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_quiz_unique
        ON quiz_questions (module_id, question)
        """
    )

    conn.commit()
    conn.close()


def seed_quiz_questions():
    """
    One-time seed from repo file: data/quiz_questions.csv
    - Safe to run on every startup due to unique index + INSERT OR IGNORE
    - If table already has questions, we skip seeding.
    """
    seed_path = os.path.join(BASE_DIR, "data", "quiz_questions.csv")
    if not os.path.exists(seed_path):
        return

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS cnt FROM quiz_questions")
    existing = cur.fetchone()["cnt"] or 0
    if existing > 0:
        conn.close()
        return

    with open(seed_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            module_id = (row.get("module_id") or row.get("Module ID") or "").strip()
            question = (row.get("question") or row.get("Question") or "").strip()

            answer_a = (row.get("answer_a") or row.get("Answer A") or "").strip()
            answer_b = (row.get("answer_b") or row.get("Answer B") or "").strip()
            answer_c = (row.get("answer_c") or row.get("Answer C") or "").strip()
            answer_d = (row.get("answer_d") or row.get("Answer D") or "").strip()

            correct_option = (row.get("correct_option") or row.get("Correct Option") or "").strip().upper()

            if not module_id or not question or correct_option not in {"A", "B", "C", "D"}:
                continue
            if not (answer_a and answer_b and answer_c and answer_d):
                continue

            cur.execute(
                """
                INSERT OR IGNORE INTO quiz_questions
                (module_id, question, answer_a, answer_b, answer_c, answer_d, correct_option, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (module_id, question, answer_a, answer_b, answer_c, answer_d, correct_option),
            )

    conn.commit()
    conn.close()


# Initialize database + seed quizzes at startup
with app.app_context():
    init_db()
    seed_quiz_questions()

# -------------------------
# Auth / helpers
# -------------------------
def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM employees WHERE id=?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def ensure_progress_rows(employee_id: int):
    conn = get_db()
    cur = conn.cursor()
    for module_id, _ in MODULES:
        cur.execute(
            "SELECT id FROM progress WHERE employee_id=? AND module_id=?",
            (employee_id, module_id),
        )
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO progress (employee_id, module_id, status) VALUES (?, ?, ?)",
                (employee_id, module_id, "not_started"),
            )
    conn.commit()
    conn.close()


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user["role"] != "admin":
            flash("Admin access required.", "danger")
            if user:
                return redirect(url_for("dashboard"))
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM employees WHERE email=?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Self-registration: first user becomes admin, others staff
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not (first_name and last_name and email and password):
            flash("All fields are required.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) AS cnt FROM employees")
        count = (cur.fetchone()["cnt"] or 0)
        role = "admin" if count == 0 else "staff"

        try:
            cur.execute(
                """
                INSERT INTO employees (first_name, last_name, email, password, role)
                VALUES (?, ?, ?, ?, ?)
                """,
                (first_name, last_name, email, password_hash, role),
            )
            conn.commit()
            new_id = cur.lastrowid
            conn.close()

            ensure_progress_rows(new_id)

            if role == "admin":
                flash("Registration successful. You are the first user and have been set as ADMIN.", "success")
            else:
                flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            flash("An account with that email already exists.", "danger")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    ensure_progress_rows(user["id"])

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT module_id, best_score, status, date_completed FROM progress WHERE employee_id=?",
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    progress_map = {row["module_id"]: row for row in rows}

    module_status = []
    for module_id, title in MODULES:
        p = progress_map.get(module_id)
        module_status.append(
            {
                "id": module_id,
                "title": title,
                "status": p["status"] if p else "not_started",
                "best_score": p["best_score"] if p else None,
                "date_completed": p["date_completed"] if p else None,
            }
        )

    all_done = all((m["status"] == "completed" and (m["best_score"] or 0) >= 80) for m in module_status)

    return render_template("dashboard.html", user=user, modules=module_status, all_done=all_done)


@app.route("/module/<module_id>", methods=["GET", "POST"])
def module_view(module_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    title = next((t for mid, t in MODULES if mid == module_id), None)
    if not title:
        flash("Module not found.", "danger")
        return redirect(url_for("dashboard"))

    # POST: save score entered by user (optional/manual)
    if request.method == "POST":
        try:
            score = int(request.form.get("score", "").strip())
        except Exception:
            flash("Please enter a valid numeric score.", "danger")
            return redirect(url_for("module_view", module_id=module_id))

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, best_score FROM progress WHERE employee_id=? AND module_id=?", (user["id"], module_id))
        row = cur.fetchone()

        status = "completed" if score >= 80 else "in_progress"
        date_completed = datetime.now().strftime("%Y-%m-%d") if status == "completed" else None

        if row:
            best = row["best_score"] or 0
            best_score = max(best, score)
            cur.execute(
                """
                UPDATE progress
                SET best_score=?, status=?, date_completed=?
                WHERE id=?
                """,
                (best_score, status, date_completed, row["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO progress (employee_id, module_id, best_score, status, date_completed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user["id"], module_id, score, status, date_completed),
            )

        conn.commit()
        conn.close()

        flash("Score saved.", "success")
        return redirect(url_for("dashboard"))

    # GET: load lesson content from modules/M#.md
    lesson_path = os.path.join(BASE_DIR, "modules", f"{module_id}.md")
    if os.path.exists(lesson_path):
        with open(lesson_path, "r", encoding="utf-8", errors="replace") as f:
            md_text = f.read()
        lesson_html = markdown.markdown(md_text, extensions=["extra"])
    else:
        lesson_html = "<p><em>Lesson content not uploaded yet.</em></p>"

    return render_template("module.html", module_id=module_id, title=title, user=user, lesson_html=lesson_html)


@app.route("/quiz/<module_id>", methods=["GET", "POST"])
def take_quiz(module_id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    title = next((t for mid, t in MODULES if mid == module_id), None)
    if not title:
        flash("Module not found.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, question, answer_a, answer_b, answer_c, answer_d, correct_option
        FROM quiz_questions
        WHERE module_id=? AND active=1
        ORDER BY RANDOM()
        LIMIT 10
        """,
        (module_id,),
    )
    questions = cur.fetchall()

    if not questions:
        conn.close()
        flash("No quiz questions loaded yet. Admin must import or seed the quiz bank.", "warning")
        return redirect(url_for("module_view", module_id=module_id))

    if request.method == "POST":
        correct = 0
        total = len(questions)

        for q in questions:
            chosen = (request.form.get(f"q_{q['id']}") or "").strip().upper()
            if chosen == (q["correct_option"] or "").strip().upper():
                correct += 1

        score = int(round((correct / total) * 100))
        passed = 1 if score >= 80 else 0

        # Save attempt
        cur.execute(
            """
            INSERT INTO quiz_attempts (employee_id, module_id, score, total_questions, passed, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user["id"], module_id, score, total, passed, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

        # Update progress
        cur.execute("SELECT id, best_score FROM progress WHERE employee_id=? AND module_id=?", (user["id"], module_id))
        row = cur.fetchone()

        status = "completed" if passed else "in_progress"
        date_completed = datetime.now().strftime("%Y-%m-%d") if passed else None

        if row:
            best = row["best_score"] or 0
            best_score = max(best, score)
            cur.execute(
                """
                UPDATE progress
                SET best_score=?, status=?, date_completed=?
                WHERE id=?
                """,
                (best_score, status, date_completed, row["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO progress (employee_id, module_id, best_score, status, date_completed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user["id"], module_id, score, status, date_completed),
            )

        conn.commit()
        conn.close()

        flash(f"Quiz submitted. Score: {score}%.", "success" if passed else "warning")
        return redirect(url_for("dashboard"))

    conn.close()
    return render_template("quiz.html", module_id=module_id, title=title, questions=questions)


@app.route("/admin/import-quiz", methods=["GET", "POST"])
@admin_required
def import_quiz():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename.strip() == "":
            flash("No file uploaded.", "danger")
            return redirect(url_for("import_quiz"))

        raw = file.stream.read()

        # Handle CSVs exported from Excel/Windows with CP1252 "smart quotes"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")

        lines = text.splitlines()
        reader = csv.DictReader(lines)

        conn = get_db()
        cur = conn.cursor()

        inserted = 0
        skipped = 0

        for row in reader:
            module_id = (row.get("module_id") or row.get("Module ID") or "").strip()
            question = (row.get("question") or row.get("Question") or "").strip()

            answer_a = (row.get("answer_a") or row.get("Answer A") or "").strip()
            answer_b = (row.get("answer_b") or row.get("Answer B") or "").strip()
            answer_c = (row.get("answer_c") or row.get("Answer C") or "").strip()
            answer_d = (row.get("answer_d") or row.get("Answer D") or "").strip()

            correct_option = (row.get("correct_option") or row.get("Correct Option") or "").strip().upper()

            if not module_id or not question or correct_option not in {"A", "B", "C", "D"}:
                skipped += 1
                continue

            if not (answer_a and answer_b and answer_c and answer_d):
                skipped += 1
                continue

            cur.execute(
                """
                INSERT OR IGNORE INTO quiz_questions
                (module_id, question, answer_a, answer_b, answer_c, answer_d, correct_option, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (module_id, question, answer_a, answer_b, answer_c, answer_d, correct_option),
            )
            inserted += 1

        conn.commit()
        conn.close()

        flash(f"Import complete. Inserted: {inserted}. Skipped: {skipped}.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("import_quiz.html")


@app.route("/certificate")
def certificate():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT module_id, best_score, status, date_completed FROM progress WHERE employee_id=?",
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    progress_map = {row["module_id"]: row for row in rows}
    module_status = []
    for module_id, title in MODULES:
        p = progress_map.get(module_id)
        module_status.append(
            {
                "id": module_id,
                "title": title,
                "status": p["status"] if p else "not_started",
                "best_score": p["best_score"] if p else None,
                "date_completed": p["date_completed"] if p else None,
            }
        )

    all_done = all((m["status"] == "completed" and (m["best_score"] or 0) >= 80) for m in module_status)

    if not all_done:
        flash("You have not completed all required modules with a passing score.", "warning")
        return redirect(url_for("dashboard"))

    completion_date = max(m["date_completed"] for m in module_status if m["date_completed"])

    return render_template(
        "certificate.html",
        user=user,
        modules=module_status,
        completion_date=completion_date,
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    user = get_current_user()

    module_filter = request.args.get("module_id", "all")
    start_date = request.args.get("start_date") or ""
    end_date = request.args.get("end_date") or ""

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM employees ORDER BY last_name, first_name")
    employees = cur.fetchall()

    summaries = []

    for emp in employees:
        conditions = ["employee_id = ?"]
        params = [emp["id"]]

        if module_filter != "all":
            conditions.append("module_id = ?")
            params.append(module_filter)

        if start_date:
            conditions.append("date_completed >= ?")
            params.append(start_date)
        if end_date:
            conditions.append("date_completed <= ?")
            params.append(end_date)

        where_clause = " AND ".join(conditions)

        cur.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status='completed' AND (best_score >= 80) THEN 1 ELSE 0 END) AS completed
            FROM progress
            WHERE {where_clause}
            """,
            tuple(params),
        )
        counts = cur.fetchone()
        total = counts["total"] or 0
        completed = counts["completed"] or 0

        summaries.append(
            {
                "id": emp["id"],
                "name": f"{emp['first_name']} {emp['last_name']}",
                "email": emp["email"],
                "role": emp["role"],
                "modules_completed": completed,
                "modules_total": total,
            }
        )

    conn.close()

    return render_template(
        "admin.html",
        user=user,
        summaries=summaries,
        modules=MODULES,
        module_filter=module_filter,
        start_date=start_date,
        end_date=end_date,
    )


@app.route("/admin/export")
@admin_required
def admin_export():
    module_filter = request.args.get("module_id", "all")
    start_date = request.args.get("start_date") or ""
    end_date = request.args.get("end_date") or ""

    conn = get_db()
    cur = conn.cursor()

    conditions = ["1=1"]
    params = []

    if module_filter != "all":
        conditions.append("p.module_id = ?")
        params.append(module_filter)

    if start_date:
        conditions.append("p.date_completed >= ?")
        params.append(start_date)

    if end_date:
        conditions.append("p.date_completed <= ?")
        params.append(end_date)

    where_clause = " AND ".join(conditions)

    cur.execute(
        f"""
        SELECT
            e.first_name, e.last_name, e.email, e.role,
            p.module_id, p.best_score, p.status, p.date_completed
        FROM employees e
        LEFT JOIN progress p ON e.id = p.employee_id
        WHERE {where_clause}
        ORDER BY e.last_name, e.first_name, p.module_id
        """,
        tuple(params),
    )
    rows = cur.fetchall()
    conn.close()

    module_titles = dict(MODULES)

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(
        [
            "First Name",
            "Last Name",
            "Email",
            "Role",
            "Module ID",
            "Module Title",
            "Best Score",
            "Status",
            "Date Completed",
        ]
    )

    for r in rows:
        writer.writerow(
            [
                r["first_name"],
                r["last_name"],
                r["email"],
                r["role"],
                r["module_id"] or "",
                module_titles.get(r["module_id"], "") if r["module_id"] else "",
                r["best_score"] if r["best_score"] is not None else "",
                r["status"] or "",
                r["date_completed"] or "",
            ]
        )

    output = si.getvalue()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cfm_training_export.csv"},
    )

@app.route("/admin/quiz-counts")
@admin_required
def quiz_counts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT module_id, COUNT(*) AS cnt
        FROM quiz_questions
        WHERE active = 1
        GROUP BY module_id
        ORDER BY module_id
    """)
    rows = cur.fetchall()
    conn.close()

    return "<br>".join([f"{r['module_id']}: {r['cnt']}" for r in rows])

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # For local development only
    app.run(debug=True)
