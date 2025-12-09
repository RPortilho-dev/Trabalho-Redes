from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import time

app = Flask(__name__)
CORS(app)

client = MongoClient("mongodb://mongodb:27017/")
db = client["devops_monitor"]
colecao_metricas = db["metricas"]
colecao_logs = db["logs_seguranca"]

# --- CONTROLE DE SEGURANÇA (DDoS) ---
monitor_ddos = {"contagem": 0, "inicio_janela": time.time(), "bloqueado": False}

def checar_ddos():
    agora = time.time()
    if agora - monitor_ddos["inicio_janela"] > 10:
        monitor_ddos["contagem"] = 0
        monitor_ddos["inicio_janela"] = agora
        monitor_ddos["bloqueado"] = False
    
    monitor_ddos["contagem"] += 1
    if monitor_ddos["contagem"] > 50:
        monitor_ddos["bloqueado"] = True
        return True
    return False

# --- MOTOR DE REGRAS DE ALERTA (REQUISITO 4) ---
def processar_regras_alerta(dados):
    nivel = "VERDE"
    mensagem = "OK"
    enviar_email = False
    servico = dados.get("servico")
    
    # 1. WEB SERVER
    if servico == "web_server":
        if dados.get("status_code") != 200:
            nivel = "VERMELHO"; mensagem = f"Crítico: Web Indisponível (Status {dados.get('status_code')})"; enviar_email = True
        elif dados.get("latencia_ms", 0) > 1000:
            nivel = "AMARELO"; mensagem = f"Atenção: Latência Web Alta ({dados.get('latencia_ms')}ms)"; enviar_email = True

    # 2. HOST / CPU
    elif servico == "host_stats":
        if dados.get("cpu_uso", 0) > 90:
            nivel = "VERMELHO"; mensagem = f"Crítico: CPU Saturada ({dados.get('cpu_uso')}%)"; enviar_email = True
        elif dados.get("cpu_uso", 0) > 75:
            nivel = "AMARELO"; mensagem = f"Atenção: Carga de CPU Elevada ({dados.get('cpu_uso')}%)"; enviar_email = True

    # 3. BANCO DE DADOS
    elif servico == "banco_dados":
        if not dados.get("disponivel"):
            nivel = "VERMELHO"; mensagem = "Crítico: Banco de Dados Offline"; enviar_email = True
        elif dados.get("slow_queries", 0) > 5:
            nivel = "AMARELO"; mensagem = f"Atenção: Alto volume de Slow Queries ({dados.get('slow_queries')})"; enviar_email = True

    # 4. SMTP
    elif servico == "smtp":
        if dados.get("taxa_erro", 0) > 10:
            nivel = "VERMELHO"; mensagem = f"Crítico: Falha envio de e-mails ({dados.get('taxa_erro')}%)"; enviar_email = True
        elif dados.get("fila_emails", 0) > 50:
            nivel = "AMARELO"; mensagem = f"Atenção: Fila de e-mail cheia ({dados.get('fila_emails')})"; enviar_email = True

    # 5. SEGURANÇA (Brute Force / Vuln)
    elif servico == "autenticacao":
        if dados.get("falhas_login_minuto", 0) > 20:
            nivel = "VERMELHO"; mensagem = f"SEGURANÇA: Ataque Brute-Force Detectado ({dados.get('falhas_login_minuto')} falhas/min)"; enviar_email = True
    
    elif servico == "vulnerabilidade":
        if len(dados.get("cves_encontradas", [])) > 0:
            nivel = "VERMELHO"; mensagem = f"SEGURANÇA: Vulnerabilidade Crítica Encontrada ({dados.get('cves_encontradas')[0]})"; enviar_email = True

    # AÇÃO: SIMULAR ENVIO DE EMAIL
    if enviar_email:
        prefixo = "[URGENTE]" if nivel == "VERMELHO" else "[AVISO]"
        print(f"📧 {prefixo} Enviando e-mail para admin@sysops.com: {mensagem}")
        
        # Salva Log
        colecao_logs.insert_one({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "alvo": servico.upper(),
            "status": nivel,
            "mensagem": mensagem
        })

# --- ROTAS ---

@app.route('/api/ingestao', methods=['POST'])
def receber_metricas():
    # Segurança DDoS (Prioridade Máxima)
    if checar_ddos():
        print(f"!!! ALERTA DDOS !!! ({monitor_ddos['contagem']} reqs/10s)")
        colecao_logs.insert_one({"timestamp": datetime.now().strftime("%H:%M:%S"), "alvo": "REDE", "status": "CRÍTICO", "mensagem": "DDoS Detectado - Tráfego Bloqueado"})
        
    try:
        dados = request.json
        dados['timestamp'] = datetime.now().strftime("%H:%M:%S")
        
        # Aplica Regras de Negócio (Alertas)
        processar_regras_alerta(dados)
        
        # Regra específica do Agente (FIM - File Integrity)
        if dados.get('servico') == 'seguranca_arquivo':
            colecao_logs.insert_one({"timestamp": datetime.now().strftime("%H:%M:%S"), "alvo": dados['alvo'], "status": "ALTERADO", "mensagem": dados['mensagem']})

        colecao_metricas.insert_one(dados)
        return jsonify({"status": "recebido"}), 201
    except Exception as e:
        return jsonify({"erro": str(e)}), 500

@app.route('/api/metricas', methods=['GET'])
def obter_metricas():
    return jsonify(list(colecao_metricas.find({}, {'_id': 0}).sort("_id", -1).limit(60)))

@app.route('/api/logs', methods=['GET'])
def obter_logs():
    return jsonify(list(colecao_logs.find({}, {'_id': 0}).sort("_id", -1).limit(20)))

@app.route('/api/seguranca', methods=['GET'])
def status_seguranca():
    return jsonify({"sob_ataque": monitor_ddos["bloqueado"], "total_reqs": monitor_ddos["contagem"]})

if __name__ == '__main__':
    print("Backend Iniciado na porta 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)