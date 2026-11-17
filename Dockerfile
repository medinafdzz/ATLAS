FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -r -u 10001 atlas
USER atlas
EXPOSE 8000
CMD ["atlas", "serve", "--host", "0.0.0.0"]
