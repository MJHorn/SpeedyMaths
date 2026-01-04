from flask import Flask, render_template, request, redirect
from decimal import Decimal
import random
import os

app = Flask(__name__)

@app.before_request
def before_request():
    if request.headers.get('X-Forwarded-Proto', 'http') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/')
def home():
    return render_template('difficulty.html')

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        difficulty = request.form['difficulty']
        num_problems = 40
        problems = generate_problems(difficulty, num_problems)
        return render_template('quiz_with_results.html', problems=problems)
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
    return render_template('score.html', score=num_correct, user_answers=results)

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
