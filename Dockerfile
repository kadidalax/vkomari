FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py config.py db.py auth.py agent.py scheduler.py ./
COPY reporters/ ./reporters/
COPY routes/ ./routes/
COPY static/ ./static/

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
