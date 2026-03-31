FROM python:3.11-slim
WORKDIR /app
RUN echo "FLAG{xxe_3xt3rn4l_3nt1ty_r34d}" > /flag.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
EXPOSE 5000
CMD ["python", "src/app.py"]
