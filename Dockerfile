FROM python:3.12-slim
WORKDIR /app
COPY . .
ENV PORT=8000
ENV HOST=0.0.0.0
EXPOSE 8000
VOLUME ["/app/data"]
CMD ["python", "app/server.py"]

