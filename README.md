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


## Deploy the full application to Vercel

This repository includes a Vercel configuration at the repository root, a Python serverless entry point at `api/index.py`, the React/Vite frontend in `frontend/`, and the FastAPI application in `backend/`.

1. Import this GitHub repository into Vercel.
2. Set **Root Directory** to `./` (repository root).
3. Use the included `vercel.json` settings. The frontend build output is `frontend/dist`.
4. Deploy. The frontend calls API endpoints using relative `/api` paths.

**Storage note:** SQLite on Vercel uses temporary serverless storage; changes may not persist. Configure a managed database using `DATABASE_URL` for durable records. The bundled patient data is synthetic and this is not a clinical diagnostic tool. Test the deployment after publishing.
