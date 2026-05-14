# Imagen base con versión fijada (buena práctica)
FROM python:3.12-slim

# Crear usuario no-root (buena práctica - OWASP A05)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copiar dependencias primero para cache de capas
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Inicializar la base de datos al iniciar
RUN python -c "import app; app.init_db()" || true

# Cambiar al usuario no-root
USER appuser

EXPOSE 5000

# Usar gunicorn en lugar de Flask dev server en producción
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
