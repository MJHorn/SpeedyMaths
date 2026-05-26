from flask import Flask, render_template, request, redirect, session, g, jsonify
from decimal import Decimal
import random
import os
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")


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

@app.route('/record', methods=['POST'])
def record():
    # Stub record endpoint to keep frontend javascript from throwing errors
    return jsonify({"ok": True, "message": "Database and tracking are disabled."})

def generate_problems(difficulty, num_problems):
    problems = []
    levelproblems = {}
    levelproblems['Level 1'] = [[m, n] for m in [2,5,10] for n in range(1, 11)]
    levelproblems['Level 2'] = [[m, n] for m in [2,3,4,5,10,11] for n in range(1, 11)]
    levelproblems['Level 3'] = [[m, n] for m in [2,3,4,5,6,9,10,11] for n in range(1, 11)]
    levelproblems['Level 4'] = [[m, n] for m in [2,3,4,5,6,7,8,9,10,11,12] for n in range(1, 13)]
    levelproblems['Level 5'] = [[Decimal(10)**a*Decimal(m), Decimal(10)**b*Decimal(n)] for m in [2,3,4,5,6,7,8,9,10,11,12] for n in range(1, 13) for a in range(-1,2) for b in range(-1,2)]
    levelproblems['Level 6'] = [[Decimal(10)**a*Decimal(m), Decimal(10)**b*Decimal(n)] for m in [2,3,4,5,6,7,8,9,10,11,12,13,14,15] for n in range(1, 16) for a in range(-2,3) for b in range(-2,3)]

    problemSet = levelproblems[difficulty].copy()
    for i in range(num_problems):
        if len(problemSet) == 0:
            problemSet = levelproblems[difficulty].copy()
        problem = random.choice(problemSet)
        problemSet.remove(problem)
        x = problem[0]
        y = problem[1]
        solution = x*y
        problem = [f'{str(x)} x {str(y)}', str(solution)]
        problems.append(problem)
    return problems

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
