FROM python:3.11-slim
WORKDIR /app
RUN echo "FLAG{cmd_1nj3ct10n_0s_syst3m_pwn3d}" > /flag.txt && chmod 644 /flag.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
EXPOSE 5000
CMD ["python", "src/app.py"]
