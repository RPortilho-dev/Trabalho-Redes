import requests
import time
import threading

API_URL = "http://localhost:5000/api/ingestao"

def atacar():
    payload = {"servico": "ataque_falso", "dados": "lixo"}
    try:
        r = requests.post(API_URL, json=payload)
        print(f"Ataque enviado: {r.status_code}")
    except:
        print("Servidor caiu ou recusou conexão!")

print("--- INICIANDO SIMULAÇÃO DE DDOS ---")
print("Disparando 100 requisições simultâneas...")

threads = []
for i in range(100):
    t = threading.Thread(target=atacar)
    threads.append(t)
    t.start()
    time.sleep(0.01) # Pequeno delay para não travar seu PC, mas rápido o suficiente para o servidor

print("--- ATAQUE FINALIZADO ---")