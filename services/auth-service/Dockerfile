FROM python:3.12-slim

# Create non-root user with UID 1000 to match K8s runAsUser: 1000
RUN groupadd --system --gid 1000 app \
 && useradd --system --uid 1000 --gid app --create-home app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# App files owned by the non-root user
RUN chown -R app:app /app

# CK-02 / IV-05 remediated: run as non-root
USER app

EXPOSE 5001

# HEALTHCHECK using Python stdlib (no curl in slim image)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5001/').status==200 else 1)" || exit 1

CMD ["python", "app.py"]