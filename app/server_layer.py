# flask_server_simulado.py
from flask import Flask, request
import time
import random

app = Flask(__name__)

@app.route("/")
def homepage():
    time.sleep(0.1)  # pequena carga
    return "Bem-vindo à página inicial!"

@app.route("/login")
def login():
    time.sleep(0.5)  # simula autenticação (ex: consulta ao banco)
    return "Login simulado com sucesso!"

@app.route("/busca")
def busca():
    query = request.args.get('q', 'nada')
    time.sleep(random.uniform(0.3, 1.0))  # simula busca com variação
    return f"Resultados para busca: {query}"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5100, threaded=True)
