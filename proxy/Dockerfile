FROM python:3.12-slim

RUN useradd -m mitmuser

RUN pip install --no-cache-dir mitmproxy==12.2.1 aiosqlite

WORKDIR /app
COPY scanner.py addon.py /app/

USER mitmuser

CMD ["mitmdump", \
     "--listen-host", "0.0.0.0", \
     "--listen-port", "8082", \
     "--set", "confdir=/home/mitmuser/.mitmproxy", \
     "--set", "ssl_insecure=true", \
     "-s", "/app/addon.py"]
