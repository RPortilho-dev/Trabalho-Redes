# Dockerfile
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia e instala as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código
COPY . /app

# Comando de execução será definido no docker-compose.yml