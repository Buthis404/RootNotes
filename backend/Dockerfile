FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    netcat-openbsd \
    util-linux \
    coreutils \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    libjpeg62-turbo \
    libopenjp2-7 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin rootnotes

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .

RUN chown -R rootnotes:rootnotes /app

USER rootnotes

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
