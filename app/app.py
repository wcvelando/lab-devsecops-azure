"""
Aplicación de registros de estudiantes - Student Records App
NOTA DOCENTE: Esta app contiene vulnerabilidades INTENCIONALES para el lab de seguridad.
Los estudiantes deben identificarlas mediante las herramientas del pipeline.
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# VULNERABILIDAD INTENCIONAL #1 (A02 - Cryptographic Failures):
# Secreto hardcodeado en código fuente. Semgrep y Gitleaks deben detectarlo.
SECRET_KEY = "super-secret-key-12345"
DB_PASSWORD = "admin123"  # hardcoded credential

# VULNERABILIDAD INTENCIONAL #2 (A05 - Security Misconfiguration):
# Debug mode activo en producción
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = SECRET_KEY

DB_PATH = os.environ.get("DB_PATH", "/tmp/students.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            grade TEXT
        )
    """)
    conn.execute("INSERT OR IGNORE INTO students (id, name, email, grade) VALUES (1, 'Ana García', 'ana@example.com', 'A')")
    conn.execute("INSERT OR IGNORE INTO students (id, name, email, grade) VALUES (2, 'Luis Pérez', 'luis@example.com', 'B')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"message": "Student Records API", "version": "1.0"})


@app.route("/students", methods=["GET"])
def get_students():
    conn = get_db()
    students = conn.execute("SELECT * FROM students").fetchall()
    conn.close()
    return jsonify([dict(s) for s in students])


@app.route("/students/search", methods=["GET"])
def search_students():
    # VULNERABILIDAD INTENCIONAL #3 (A03 - Injection):
    # SQL Injection: el parámetro name se concatena directamente sin sanitización.
    # ZAP y Semgrep deben detectarlo.
    name = request.args.get("name", "")
    conn = get_db()
    # ❌ VULNERABLE: f-string directo en SQL
    query = f"SELECT * FROM students WHERE name LIKE '%{name}%'"
    students = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(s) for s in students])


@app.route("/students", methods=["POST"])
def add_student():
    data = request.get_json()
    if not data or "name" not in data or "email" not in data:
        return jsonify({"error": "name and email required"}), 400
    conn = get_db()
    conn.execute(
        "INSERT INTO students (name, email, grade) VALUES (?, ?, ?)",
        (data["name"], data["email"], data.get("grade", ""))
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Student added"}), 201


@app.route("/students/<int:student_id>", methods=["DELETE"])
def delete_student(student_id):
    conn = get_db()
    conn.execute("DELETE FROM students WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Student deleted"})


@app.route("/students/<int:student_id>", methods=["PUT"])
def update_student(student_id):
    data = request.get_json()
    conn = get_db()
    conn.execute(
        "UPDATE students SET name=?, email=?, grade=? WHERE id=?",
        (data.get("name"), data.get("email"), data.get("grade"), student_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Student updated"})


if __name__ == "__main__":
    init_db()
    # VULNERABILIDAD INTENCIONAL #4 (A05): host="0.0.0.0" sin TLS ni autenticación
    app.run(host="0.0.0.0", port=5000, debug=True)
