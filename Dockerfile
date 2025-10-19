# Use Python base image
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
    build-essential \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libxml2 \
    libxslt1.1 \
    libjpeg-dev \
    libglib2.0-0 \        
    fonts-liberation \
    fonts-dejavu-core \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ---- Install Nikto (stable + self-contained) ----
RUN apt-get update && \
    apt-get install -y git perl make gcc g++ curl \
    libwww-perl libio-socket-ssl-perl libnet-ssleay-perl liburi-perl ca-certificates && \
    git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto


# Set working directory inside container
WORKDIR /app

# System updates for security patches
RUN apt-get update && apt-get upgrade -y && apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose Flask port
EXPOSE 5001

# Run Flask app
CMD ["python", "run.py"]

