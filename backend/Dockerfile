FROM python:3.11-slim

WORKDIR /app

# Install system dependency
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python library
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy semua kode backend
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]