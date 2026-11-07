FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; else pip install --no-cache-dir flask; fi
EXPOSE 5000
ENV FLASK_APP=app.py FLASK_RUN_HOST=0.0.0.0 FLASK_RUN_PORT=5000 PORT=5000 FLASK_DEBUG=0
CMD ["sh", "-c", "python app.py || flask run --host=0.0.0.0 --port=5000"]
