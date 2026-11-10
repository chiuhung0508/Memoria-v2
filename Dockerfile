FROM python:3.12-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates ffmpeg sqlite3 && rm -rf /var/lib/apt/lists/*
COPY server.py /app/server.py
COPY dist /app/dist
COPY media_sources /app/media_sources
RUN mkdir -p /data
EXPOSE 8080
ENV HOST="0.0.0.0"
ENV PORT="8080"
ENV DB_PATH="/data/memoria.db"
ENV PYTHONUNBUFFERED="1"
CMD ["python3", "/app/server.py"]
