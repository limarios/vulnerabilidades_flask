# ddos_simulation.py
import threading
import requests

TARGET = "http://127.0.0.1:5100/"
NUM_THREADS = 1000  # Número de requisições simultâneas (simulando bots)

def attack():
    try:
        response = requests.get(TARGET)
        print(f"Status: {response.status_code}")
    except Exception as e:
        print(f"Erro: {e}")

threads = []

for i in range(NUM_THREADS):
    t = threading.Thread(target=attack)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
