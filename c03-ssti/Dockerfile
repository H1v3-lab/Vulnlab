FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Fichier secret lisible via RCE (récompense de l'exploit)
RUN echo "FLAG{sst1_j1nj4_rc3_p0wn3d}" > /flag.txt && \
    echo "DB_PASSWORD=sup3r_s3cr3t_db_pwd" >> /etc/environment && \
    chmod 644 /flag.txt

EXPOSE 5000
CMD ["python", "src/app.py"]
