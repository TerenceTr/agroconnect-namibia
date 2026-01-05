AgroConnect — Backend (refactor)

1. Create a Python venv:
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows

2. Install deps:
pip install -r requirements.txt

3. Set env variables (example):
export FLASK_APP=app.py
export FLASK_ENV=development
export DATABASE_URL=postgresql://postgres:password@localhost:5432/agroconnect
export JWT_SECRET=supersecret
export SECRET_KEY=dev-secret

4. Initialize DB:
python -c "from app import create_app; app=create_app(); from database.db import db; with app.app_context(): db.create_all()"

5. Run:
flask run

Notes:
- For production use migrations (Alembic) and proper SMTP provider for send_email.
- Endpoints kept compatible with your frontend, only internals changed and responses standardized.
