from flask import Flask, render_template, request, redirect, session, g, jsonify
from decimal import Decimal
import random
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config.setdefault("DB_INITIALIZED", False)

def get_db_url():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        return None
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return db_url

def get_db():
    if "db" not in g:
        db_url = get_db_url()
        if not db_url:
            raise RuntimeError("DATABASE_URL is not set.")
        g.db = psycopg2.connect(db_url, sslmode="require")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db_url = get_db_url()
    if not db_url:
        return
    conn = psycopg2.connect(db_url, sslmode="require")
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS progress (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        difficulty TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        total INTEGER NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    """
                )
    finally:
        conn.close()

def login_required(view_func):
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/login")
        return view_func(*args, **kwargs)
    wrapped.__name__ = view_func.__name__
    return wrapped

@app.context_processor
def inject_current_user():
    return {"current_user_email": session.get("user_email")}

@app.before_request
def before_request():
    if request.headers.get('X-Forwarded-Proto', 'http') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
    if not app.config["DB_INITIALIZED"]:
        init_db()
        app.config["DB_INITIALIZED"] = True

@app.route('/')
def home():
    return render_template('difficulty.html')

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        difficulty = request.form['difficulty']
        num_problems = 40
        problems = generate_problems(difficulty, num_problems)
        return render_template('quiz_with_results.html', problems=problems, difficulty=difficulty)
    else:
        return render_template('difficulty.html')

@app.route('/score', methods=['POST'])
def score():
    user_answers = request.form.to_dict()
    num_correct = 0
    results = []
    for problem, answer in user_answers.items():
        x, y = problem.split(' x ')
        correct_answer = str(int(x) * int(y))
        result = {'problem': problem, 'user_answer': answer, 'correct_answer': correct_answer}
        results.append(result)
        if answer == correct_answer:
            num_correct += 1
    if session.get("user_id"):
        save_progress(session["user_id"], "Mixed", num_correct, len(user_answers))
    return render_template('score.html', score=num_correct, user_answers=results)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            return render_template("register.html", error="Email and password are required.")
        if not get_db_url():
            return render_template("register.html", error="Database is not configured.")
        conn = get_db()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
                if cur.fetchone():
                    return render_template("register.html", error="Email already registered.")
                password_hash = generate_password_hash(password)
                cur.execute(
                    "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id;",
                    (email, password_hash),
                )
                user_id = cur.fetchone()["id"]
        session["user_id"] = user_id
        session["user_email"] = email
        return redirect("/progress")
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            return render_template("login.html", error="Email and password are required.")
        if not get_db_url():
            return render_template("login.html", error="Database is not configured.")
        conn = get_db()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, password_hash FROM users WHERE email = %s;", (email,))
                user = cur.fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Invalid email or password.")
        session["user_id"] = user["id"]
        session["user_email"] = email
        return redirect("/progress")
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

@app.route('/progress')
@login_required
def progress():
    conn = get_db()
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT difficulty, score, total, created_at
                FROM progress
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 50;
                """,
                (session["user_id"],),
            )
            attempts = cur.fetchall()
            cur.execute(
                """
                SELECT difficulty, COUNT(*) AS attempts, MAX(score) AS best_score, MAX(total) AS total
                FROM progress
                WHERE user_id = %s
                GROUP BY difficulty
                ORDER BY difficulty;
                """,
                (session["user_id"],),
            )
            summary = cur.fetchall()
    return render_template("progress.html", attempts=attempts, summary=summary)

@app.route('/record', methods=['POST'])
def record():
    if not session.get("user_id"):
        return ("", 204)
    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "Unknown")
    score = data.get("score")
    total = data.get("total")
    if score is None or total is None:
        return jsonify({"error": "Missing score data."}), 400
    save_progress(session["user_id"], difficulty, int(score), int(total))
    return jsonify({"ok": True})

def save_progress(user_id, difficulty, score, total):
    conn = get_db()
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO progress (user_id, difficulty, score, total) VALUES (%s, %s, %s, %s);",
                (user_id, difficulty, score, total),
            )

def generate_problems(difficulty, num_problems):
    # Level 1 - 2s, 5s, 10s - by 1-10 excl 2,5,10
    # Level 2 - 2s, 3s, 4s, 5s, 10s
    # Level 3 - 2s, 3s, 4s, 5s, 6s, 9s, 10s
    # Level 4 - 2s, 3s, 4s, 5s, 6s, 7s, 8s, 9s, 10s
    # Level 5 - 2s, 3s, 4s, 5s, 6s, 7s, 8s, 9s, 10s, 11s, 12s
    # Level 6 - extra hard decimals (0.01-100 scale) with 2s-15s
    problems = []
    levelproblems = {}
    levelproblems['Level 1'] = [[m, n] for m in [2,5,10] for n in range(1, 11)]
    levelproblems['Level 2'] = [[m, n] for m in [2,3,4,5,10,11] for n in range(1, 11)]
    levelproblems['Level 3'] = [[m, n] for m in [2,3,4,5,6,9,10,11] for n in range(1, 11)]
    levelproblems['Level 4'] = [[m, n] for m in [2,3,4,5,6,7,8,9,10,11,12] for n in range(1, 13)]
    levelproblems['Level 5'] = [[Decimal(10)**a*Decimal(m), Decimal(10)**b*Decimal(n)] for m in [2,3,4,5,6,7,8,9,10,11,12] for n in range(1, 13) for a in range(-1,2) for b in range(-1,2)]
    levelproblems['Level 6'] = [[Decimal(10)**a*Decimal(m), Decimal(10)**b*Decimal(n)] for m in [2,3,4,5,6,7,8,9,10,11,12,13,14,15] for n in range(1, 16) for a in range(-2,3) for b in range(-2,3)]

    # previousProblem = []
    problemSet = levelproblems[difficulty].copy()
    for i in range(num_problems):
        if len(problemSet) == 0:
            problemSet = levelproblems[difficulty].copy()
        problem = random.choice(problemSet)
        problemSet.remove(problem)
        #while problem == previousProblem:
        #    problem = random.choice(levelproblems[difficulty])
        previousProblem = problem
        x = problem[0]
        y = problem[1]
        solution = x*y
        problem = [f'{str(x)} x {str(y)}', str(solution)]
        problems.append(problem)
    return problems

def mark_problems(user_answers):
    num_correct = 0
    for problem, answer in user_answers.items():
        x, y = problem.split(' x ')
        try:
            correct_answer = str(int(x) * int(y))
        except:
            correct_answer = str(float(x) * float(y))
        if answer == correct_answer:
            num_correct += 1
    return num_correct

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
