from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
CORS(app)

# Conexão com o Banco de Dados
client = MongoClient("mongodb://localhost:27017/")
db = client["devops_monitor"]
colecao_metricas = db["metricas"]
colecao_logs = db["logs_seguranca"]

# --- CONFIGURAÇÃO DE E-MAIL (SEUS DADOS) ---
CONFIG_EMAIL = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "remetente": "renatoportilho79@gmail.com",
    # Senha de App (sem espaços para garantir a conexão)
    "senha_app": "vqukujarszuutcvw", 
    # Enviando para você mesmo para testar
    "admin_email": "renatoportilho79@gmail.com" 
}

# --- FUNÇÃO DE ENVIO DE E-MAIL REAL ---
def enviar_email_real(assunto, corpo_mensagem):
    """Conecta no Gmail e envia o e-mail de alerta"""
    try:
        msg = MIMEMultipart()
        msg['From'] = CONFIG_EMAIL['remetente']
        msg['To'] = CONFIG_EMAIL['admin_email']
        msg['Subject'] = f"[MONITORAMENTO] {assunto}"

        msg.attach(MIMEText(corpo_mensagem, 'plain'))

        server = smtplib.SMTP(CONFIG_EMAIL['smtp_server'], CONFIG_EMAIL['smtp_port'])
        server.starttls() # Segurança TLS
        server.login(CONFIG_EMAIL['remetente'], CONFIG_EMAIL['senha_app'])
        text = msg.as_string()
        server.sendmail(CONFIG_EMAIL['remetente'], CONFIG_EMAIL['admin_email'], text)
        server.quit()
        
        print(f"✅ E-mail enviado com sucesso para {CONFIG_EMAIL['admin_email']}")
        return True
    except Exception as e:
        print(f"❌ Erro ao enviar e-mail: {str(e)}")
        return False

# --- CONTROLE DDOS ---
monitor_ddos = {"contagem": 0, "inicio_janela": time.time(), "bloqueado": False}

def checar_ddos():
    agora = time.time()
    # Reseta a janela de contagem a cada 10 segundos
    if agora - monitor_ddos["inicio_janela"] > 10:
        monitor_ddos["contagem"] = 0
        monitor_ddos["inicio_janela"] = agora
        monitor_ddos["bloqueado"] = False
    
    monitor_ddos["contagem"] += 1
    # Se passar de 50 requests em 10s, considera ataque
    if monitor_ddos["contagem"] > 50:
        monitor_ddos["bloqueado"] = True
        return True
    return False

# --- MOTOR DE REGRAS (ALERTAS IMEDIATOS) ---
def processar_regras_alerta(dados):
    nivel = "VERDE"
    mensagem = "OK"
    disparar_alerta = False
    servico = dados.get("servico")
    
    # 1. WEB SERVER
    if servico == "web_server":
        if dados.get("status_code") != 200:
            nivel = "VERMELHO"; mensagem = f"Web Indisponível (Status {dados.get('status_code')})"; disparar_alerta = True
        elif dados.get("latencia_ms", 0) > 1000:
            nivel = "AMARELO"; mensagem = f"Latência Alta Web ({dados.get('latencia_ms')}ms)"; disparar_alerta = True

    # 2. HOST (CPU)
    elif servico == "host_stats":
        if dados.get("cpu_uso", 0) > 90:
            nivel = "VERMELHO"; mensagem = f"CPU Crítica ({dados.get('cpu_uso')}%)"; disparar_alerta = True

    # 3. BANCO DE DADOS
    elif servico == "banco_dados":
        if not dados.get("disponivel"):
            nivel = "VERMELHO"; mensagem = "Banco de Dados Offline"; disparar_alerta = True
        elif dados.get("slow_queries", 0) > 5:
            nivel = "AMARELO"; mensagem = f"Alto volume de Slow Queries ({dados.get('slow_queries')})"; disparar_alerta = True

    # 4. SMTP
    elif servico == "smtp":
        if dados.get("taxa_erro", 0) > 10:
            nivel = "VERMELHO"; mensagem = f"Falha crítica no envio de e-mails ({dados.get('taxa_erro')}%)"; disparar_alerta = True
        elif dados.get("fila_emails", 0) > 50:
            nivel = "AMARELO"; mensagem = f"Fila de e-mail congestionada ({dados.get('fila_emails')})"; disparar_alerta = True

    # 5. SEGURANÇA (Brute-Force & Vuln)
    elif servico == "autenticacao":
        if dados.get("falhas_login_minuto", 0) > 20:
            nivel = "VERMELHO"; mensagem = f"Brute-Force Detectado ({dados.get('falhas_login_minuto')} falhas/min)"; disparar_alerta = True
    
    elif servico == "vulnerabilidade":
        cves = dados.get("cves_encontradas", [])
        if len(cves) > 0:
            nivel = "VERMELHO"; mensagem = f"Vulnerabilidade Crítica Encontrada ({cves[0]})"; disparar_alerta = True

    # AÇÃO: ENVIA E-MAIL SE NECESSÁRIO
    if disparar_alerta:
        print(f"⚠️ Alerta ({nivel}): {mensagem}. Enviando e-mail...")
        
        enviar_email_real(
            assunto=f"ALERTA {nivel}: {servico.upper()}",
            corpo_mensagem=f"O sistema detectou um incidente:\n\nServiço: {servico}\nSeveridade: {nivel}\nDetalhe: {mensagem}\nHorário: {datetime.now()}"
        )
        
        colecao_logs.insert_one({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "alvo": servico.upper(),
            "status": nivel,
            "mensagem": mensagem
        })

# --- RELATÓRIO PERIÓDICO (1 MINUTO) ---
def enviar_relatorio_periodico():
    """Roda em segundo plano e envia um resumo por e-mail a cada 60s"""
    print("🕒 Serviço de Relatório Automático Iniciado (Cada 60s)...")
    while True:
        time.sleep(60) # Espera 1 minuto
        
        # Coleta estatísticas básicas do banco
        total_logs = colecao_logs.count_documents({})
        logs_criticos = colecao_logs.count_documents({"status": "VERMELHO"})
        
        corpo = f"""
        Olá Administrador,

        Este é o seu relatório periódico de monitoramento.
        
        Horário: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
        Status do Sistema: ONLINE
        Total de Incidentes Registrados: {total_logs}
        Alertas Críticos (Vermelhos): {logs_criticos}
        
        O sistema continua operando e monitorando 24/7.
        """
        
        print("\n📧 Enviando Relatório Periódico...")
        enviar_email_real("Relatório de Status (1 Minuto)", corpo)

# --- ROTAS DA API ---

@app.route('/api/ingestao', methods=['POST'])
def receber_metricas():
    # 1. Checagem de DDoS (Prioridade)
    if checar_ddos():
        print(f"!!! ALERTA DDOS !!!")
        # Envia e-mail de DDoS se ainda não estiver bloqueado na notificação
        colecao_logs.insert_one({"timestamp": datetime.now().strftime("%H:%M:%S"), "alvo": "REDE", "status": "CRÍTICO", "mensagem": "DDoS Detectado"})
        
    try:
        dados = request.json
        dados['timestamp'] = datetime.now().strftime("%H:%M:%S")
        
        # 2. Processa Regras Gerais
        processar_regras_alerta(dados)
        
        # 3. Regra Específica de Arquivo (FIM)
        if dados.get('servico') == 'seguranca_arquivo':
            msg_arq = dados['mensagem']
            print(f"⚠️ Arquivo Modificado: {msg_arq}")
            enviar_email_real("CRÍTICO: ARQUIVO MODIFICADO", f"Alerta de Integridade (FIM):\n{msg_arq}")
            colecao_logs.insert_one({"timestamp": datetime.now().strftime("%H:%M:%S"), "alvo": dados['alvo'], "status": "ALTERADO", "mensagem": msg_arq})

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
    # Inicia a thread do relatório periódico
    threading.Thread(target=enviar_relatorio_periodico, daemon=True).start()
    
    print("Backend Rodando na porta 5000 (Com E-mail Real Ativado)...")
    app.run(host='0.0.0.0', port=5000, debug=True)