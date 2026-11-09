FROM docker.io/library/python:3.13-alpine
WORKDIR /app
COPY app.py index.html login.html blockboard.svg ./
ENV BB_PORT=8098 BB_DB=/data/blockboard.db
VOLUME /data
EXPOSE 8098
CMD ["python3", "app.py"]
