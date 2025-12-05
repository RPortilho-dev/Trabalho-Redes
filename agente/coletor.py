import time
import requests
import psutil
import smtplib
import dns.resolver
import hashlib
import os
import random
from datetime import datetime
from pymongo import MongoClient

API_URL = "http://localhost:5000/api/ingestao"
ARQUIVO_ALVO = "nginx.conf"
HASH_ANTERIOR = None

# --- FUNÇÕES DE MONITORAMENTO ---

def calcular_hash_arquivo(caminho):
    if not os.path.exists(caminho): return None
    with open(caminho, "rb") as f: return hashlib.sha256(f.read()).hexdigest()

def checar_integridade():
    global HASH_ANTERIOR
    hash_atual = calcular_hash_arquivo(ARQUIVO_ALVO)
    if HASH_ANTERIOR is None: HASH_ANTERIOR = hash_atual; return None
    if hash_atual != HASH_ANTERIOR:
        HASH_ANTERIOR = hash_atual
        return {"servico": "seguranca_arquivo", "alvo": ARQUIVO_ALVO, "status": "ALTERADO", "mensagem": f"CRÍTICO: O arquivo {ARQUIVO_ALVO} foi modificado!"}
    return None

def checar_web_server(url):
    try: r = requests.get(url, timeout=5); return {"servico": "web_server", "alvo": url, "status_code": r.status_code, "latencia_ms": round(r.elapsed.total_seconds()*1000, 2)}
    except str as e: return {"servico": "web_server", "alvo": url, "status_code": 0, "latencia_ms": 0, "erro": str(e)}

def checar_banco_dados():
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        db = client["devops_monitor"]; stats = db.command("dbStats")
        # Métricas simuladas para requisitos de tráfego
        return {"servico": "banco_dados", "disponivel": True, "tamanho_mb": round(stats['dataSize']/(1024*1024), 2), "qps": random.randint(50, 250), "slow_queries": 0 if random.random()>0.2 else random.randint(1,3)}
    except str as e: return {"servico": "banco_dados", "disponivel": False, "erro": str(e)}

def checar_dns():
    try: 
        inicio=time.time(); dns.resolver.Resolver().resolve('google.com','A'); 
        return {"servico": "dns", "tempo_resposta_ms": round((time.time()-inicio)*1000, 2), "qps": random.randint(1000,3000), "taxa_erro": round(random.uniform(0,1.5),2)}
    except str as e: return {"servico": "dns", "disponivel": False, "erro": str(e)}

def checar_smtp():
    try:
        inicio=time.time(); s=smtplib.SMTP("smtp.gmail.com", 587, timeout=5); s.starttls(); s.quit()
        entrega = round(random.uniform(95.0, 100.0), 1)
        return {"servico": "smtp", "latencia_conexao_ms": round((time.time()-inicio)*1000, 2), "fila_emails": random.randint(0,30), "taxa_entrega": entrega, "taxa_erro": round(100-entrega, 1), "volume_minuto": random.randint(20,100)}
    except str as e: return {"servico": "smtp", "latencia_conexao_ms": 0, "erro": str(e)}

def checar_servidor_host():
    try: con = len(psutil.net_connections())
    except: con = 0
    return {"servico": "host_stats", "cpu_uso": psutil.cpu_percent(interval=1), "conexoes_ativas": con}

# --- FUNÇÕES DE SEGURANÇA EXTRA (REQ 5) ---

def checar_brute_force():
    # Simula log de autenticação
    ataque = random.random() > 0.95 # 5% chance de ataque
    falhas = random.randint(30, 80) if ataque else random.randint(0, 2)
    return {"servico": "autenticacao", "falhas_login_minuto": falhas, "ip_suspeito": "192.168.1.105" if ataque else None}

def checar_vulnerabilidades():
    # Simula scanner CVE
    vulneravel = random.random() > 0.98 # 2% chance
    cves = ["CVE-2025-999 (Critical)"] if vulneravel else []
    return {"servico": "vulnerabilidade", "cves_encontradas": cves}

# --- LOOP PRINCIPAL ---

def enviar_para_api(dados):
    if not dados: return
    try: requests.post(API_URL, json=dados); print(f" -> [SUCESSO] {dados.get('servico').upper()} enviado.")
    except: print(" -> [ERRO] Backend Offline.")

def executar_monitoramento():
    print(f"\n--- Coleta: {datetime.now().strftime('%H:%M:%S')} ---")
    enviar_para_api(checar_integridade())
    enviar_para_api(checar_web_server("https://www.google.com"))
    enviar_para_api(checar_banco_dados())
    enviar_para_api(checar_dns())
    enviar_para_api(checar_smtp())
    enviar_para_api(checar_servidor_host())
    enviar_para_api(checar_brute_force())
    enviar_para_api(checar_vulnerabilidades())

if __name__ == "__main__":
    print("Agente Full Security Iniciado...")
    while True: executar_monitoramento(); time.sleep(5)