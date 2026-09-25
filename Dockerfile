# Security-investigation MCP server image.
#
# Note on layout: in this repo the "mcp_server" Python package IS the
# project root (this Dockerfile's own directory) -- there is no separate
# nested mcp_server/ subfolder to copy. db/ (schema.sql, seed.sql) is
# intentionally NOT copied in; it's only consumed by the postgres
# service via bind mounts in docker-compose.yml.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY data.py db.py mcp_server.py ./

# streamable-http transport, bound to 0.0.0.0 in mcp_server.py
EXPOSE 8000

CMD ["python", "mcp_server.py"]
