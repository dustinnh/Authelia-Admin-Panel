FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
# No Docker installation needed - Authelia watches files automatically
# and we use argon2-cffi for password hashing
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/app.py .
COPY src/admin.html .

# Expose application port
EXPOSE 5000

# Run with Gunicorn for production
# 4 workers, 60 second timeout, binding to all interfaces
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
