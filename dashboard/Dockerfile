FROM python:3.12-slim

RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn[standard]==0.32.0 \
    aiosqlite==0.20.0 \
    watchfiles==1.0.3

WORKDIR /app
COPY main.py ingestor.py db.py /app/
COPY static/ /app/static/

EXPOSE 8888

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8888"]
