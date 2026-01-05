# AgroConnect Namibia — Backend + Frontend + AI Service

This repo contains a modular backend (Flask + SQLAlchemy), a frontend (React), and an AI microservice (FastAPI).

## Layout (important files added)
- /backend
  - models.py                 # UPDATED SQLAlchemy models
  - services/
    - twilio_webhook_handler.py
    - sms_engine.py
    - phone_mapping.py
  - generate_farmer_sms_card.py
  - Dockerfile
  - requirements.txt
- /ai-service
  - app.py
  - Dockerfile
  - requirements.txt
- /frontend
  - Dockerfile
  - nginx/default.conf

## Next steps
1. Confirm DB schema matches models (run migrations).
2. Add `TWILIO_AUTH_TOKEN`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH` to backend `.env`.
3. Install `reportlab` if you want to generate PDFs.
4. Build & run via Docker Compose (I can generate an updated `docker-compose.yml` if you want).

