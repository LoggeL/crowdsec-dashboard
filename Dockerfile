FROM python:3.12-alpine
LABEL org.opencontainers.image.title="crowdsec-dashboard" \
      org.opencontainers.image.description="Hacker-Terminal-Dashboard für die CrowdSec Local API"
WORKDIR /app
COPY server.py ./
COPY static ./static
RUN adduser -D -H -u 10001 dashboard
USER dashboard
ENV LISTEN_HOST=0.0.0.0 LISTEN_PORT=3000 PYTHONUNBUFFERED=1
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${LISTEN_PORT}/healthz || exit 1
CMD ["python3", "server.py"]
