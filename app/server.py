# server.py
from flask import Flask
import time

app = Flask(__name__)

@app.route("/")
def index():
    time.sleep(0.1)  # Simula processamento para dar tempo de sobrecarregar
    return "Servidor ativo!"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5100)
