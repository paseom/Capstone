FROM python:3.11-slim

WORKDIR /app

# Install system dependency
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    perl \
    curl \
    cpanminus \
    libssl-dev \
    zlib1g-dev \
    && cpanm JSON XML::Writer \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto dari GitHub
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl
    
# Install Python library
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy semua kode backend
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]