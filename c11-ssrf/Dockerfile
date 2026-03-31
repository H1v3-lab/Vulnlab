FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
# Service interne simulé accessible uniquement depuis le container
EXPOSE 5000
CMD ["python", "src/app.py"]
