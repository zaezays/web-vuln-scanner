# Use Python base image
FROM python:3.11-slim-bookworm

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

