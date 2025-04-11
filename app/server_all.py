# servidor_vulneravel.py
from flask import Flask, request
import os
import sqlite3
import time

app = Flask(__name__)

# Simulação de banco SQLite
def get_db():
    conn = sqlite3.connect("usuarios.db")
    conn.execute("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, nome TEXT, senha TEXT)")
    conn.execute("INSERT OR IGNORE INTO usuarios VALUES (1, 'admin', '1234')")
    return conn

@app.route("/")
def index():
    return "<h1>Servidor Flask para Testes de Segurança</h1>"

# 1. SQL Injection
@app.route("/usuario")
def usuario():
    user_id = request.args.get("id", "1")
    conn = get_db()
    cursor = conn.cursor()
    try:
        query = f"SELECT * FROM usuarios WHERE id = {user_id}"
        print("Consulta:", query)
        cursor.execute(query)
        result = cursor.fetchone()
        return f"Usuário: {result}"
    except Exception as e:
        return f"Erro na consulta: {e}"

# 2. XSS
@app.route("/xss")
def xss():
    nome = request.args.get("nome", "Visitante")
    return f"<h1>Bem-vindo, {nome}!</h1>"

# 3. Brute Force
@app.route("/login")
def login():
    usuario = request.args.get("user")
    senha = request.args.get("senha")
    time.sleep(0.1)  # leve atraso
    if usuario == "admin" and senha == "1234":
        return "Login bem-sucedido!"
    return "Usuário ou senha incorretos."

# 4. Path Traversal
@app.route("/file")
def file():
    nome_arquivo = request.args.get("nome", "safe.txt")
    try:
        with open(f"./arquivos/{nome_arquivo}", "r") as f:
            return f.read()
    except Exception as e:
        return f"Erro: {e}"

# 5. Remote Code Execution (RCE)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        resultado = os.popen(f"ping -c 1 {host}").read()
        return f"<pre>{resultado}</pre>"
    except Exception as e:
        return f"Erro ao executar comando: {e}"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
