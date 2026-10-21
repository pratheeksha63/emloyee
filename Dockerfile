# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create data directory for SQLite
RUN mkdir -p /data

# Flag is injected at build time so it is baked into the image
# and never appears in source files or compose files.
ARG FLAG=CTF{3mpl0y33_p0rt4l_sqli_bypassed}
ENV FLAG=${FLAG}

# Secret key for Flask sessions
ARG SECRET_KEY
ENV SECRET_KEY=${SECRET_KEY:-changeme_override_in_production}

# Admin password is baked in so players cannot read it from source
ARG ADMIN_PASSWORD=yNT2fww0ootUbukIwZbUKfEV8fk
ENV ADMIN_PASSWORD=${ADMIN_PASSWORD}

ENV DATABASE=/data/portal.db

EXPOSE 5000

# Initialise DB then run with gunicorn for production-like behaviour
RUN pip install --no-cache-dir gunicorn

CMD python -c "import app; app.init_db()" && \
    gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 \
             --timeout 30 --access-logfile - app:app
