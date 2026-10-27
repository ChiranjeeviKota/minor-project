# Patient Similarity Network — Research Toolkit

FastAPI application with an embedded dashboard for exploring patient-similarity graphs and cognitive-assessment demo data.

## Architecture
- index.py: existing website, patient endpoints, similarity metrics, assessments, follow-ups, network and CSV flows.
- psn_research.py: additive research APIs and the Research Toolkit panel.
- tests/test_psn_research.py: standard-library unit tests for the research utilities.
- requirements.txt: runtime dependencies.
- vercel.json: Vercel Python routing.

## New research endpoints
| Endpoint | Purpose |
| --- | --- |
| GET /api/research/quality | Required-field, numeric-range, duplicate-code, cohort-label and date-format checks. |
| GET /api/research/cohorts | Cohort counts and descriptive score averages. |
| GET /api/research/domain-summary | Mean, median, spread, minimum and maximum by domain. |
| GET /api/research/centrality?threshold=85 | Thresholded network density, degree centrality and connected components. |
| GET /api/research/compare?patient_ids=1,2 | Compare two to eight profiles and rank domain score ranges. |
| GET /api/research/trends | Date-ordered aggregate follow-up trends. |
| GET /api/research/overview?threshold=85 | Combined quality, cohort, domain and network overview. |
| GET /api/research/report.json | Download a versioned JSON report. |
| GET /api/research/csv-template | Download an import-ready CSV template. |

## Run locally on Windows
    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    uvicorn index:app --reload

Open http://127.0.0.1:8000 and http://127.0.0.1:8000/docs.

## Run unit tests
    python -m unittest discover -s tests -v

## Interpretation and limitations
- Starter records are synthetic demo data.
- Similarity percentages reflect a configured formula, not biological relatedness.
- Network centrality depends on the threshold selected.
- Quality checks identify formatting/range issues and do not verify clinical accuracy.
- Cohort trends can be affected by visit schedules and cohort composition.
- This is an educational research prototype, not a medical device; do not use it for diagnosis or treatment decisions.
- Vercel's local filesystem is not durable storage. Configure a managed database before relying on persistent multi-user records.

## Deployment checklist
After a deployment is READY, verify /api/health, each research endpoint, Research Toolkit buttons, JSON/CSV downloads, patient search, network rendering, assessment saving, follow-up history, and the existing report. Build status alone does not prove every interaction works.
