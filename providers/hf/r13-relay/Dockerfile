FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir cryptography==46.0.7
WORKDIR /app
COPY crypto_box.py gateway.py synthetic_lane.py ./
USER 1000:1000
EXPOSE 7860
CMD ["python", "gateway.py"]
