# Patient Similarity Network — Final Integrated Project

Integrated academic demo combining Phases 1, 2 and 3 for an Alzheimer’s disease patient similarity network using cognitive-domain features.

## Stack
- Backend: FastAPI, SQLAlchemy, SQLite, NumPy, scikit-learn
- Frontend: React, Vite, Axios, Recharts, Lucide

## Windows setup

### Backend (PowerShell)
```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python seed.py
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

### Frontend (second PowerShell)
```powershell
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

Demo login: `demo` / `demo`.

## Research caution
The included sample dataset is synthetic and for demonstration only. Cognitive-domain graphs and model outputs are research prototypes, not clinically validated tools and must not be used for diagnosis or treatment decisions.
