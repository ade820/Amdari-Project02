FROM python:3.12-slim

RUN groupadd --system --gid 1000 app \
 && useradd --system --uid 1000 --gid app --create-home app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN chown -R app:app /app

USER app

EXPOSE 5002

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5002/').status==200 else 1)" || exit 1

CMD ["python", "app.py"]