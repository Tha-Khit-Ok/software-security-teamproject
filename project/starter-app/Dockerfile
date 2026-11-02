# NoteVault image, hardened: pinned slim base, no baked secrets, non-root user.
FROM python:3.12.16-slim-trixie

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080
CMD ["python", "app.py"]
