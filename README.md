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
- The Research Toolkit includes a patient-ID comparison control. Enter two to eight comma-separated numeric IDs to compare cognitive-domain ranges.
- This is an educational research prototype, not a medical device; do not use it for diagnosis or treatment decisions.
- Vercel's local filesystem is not durable storage. Configure a managed database before relying on persistent multi-user records.

## Deployment checklist
After a deployment is READY, verify /api/health, each research endpoint, Research Toolkit buttons, JSON/CSV downloads, patient search, network rendering, assessment saving, follow-up history, and the existing report. Build status alone does not prove every interaction works.


## Research Toolkit v2 additions
- **Filtered patient explorer API:** `GET /api/research/patients` supports query, cohort, age/score bounds, safe sort fields and pagination.
- **Domain correlation matrix:** `GET /api/research/correlations` reports Pearson coefficients and sample counts; constant or insufficient samples return null.
- **Score distributions:** `GET /api/research/distributions?bin_width=20` returns configurable score histograms.
- **Statistical outlier screen:** `GET /api/research/outliers` uses the 1.5-IQR rule and explicitly treats results as flags for review, not clinical findings.
- **Similarity path finder:** `GET /api/research/path?source_id=1&target_id=2&threshold=85` finds the shortest path in the thresholded similarity graph.
- **CSV safety preview:** `POST /api/research/csv-preview` accepts JSON `{"csv_text":"..." }`, validates up to 500 rows, and never writes to the database.
- **Filtered CSV export:** `GET /api/research/export.csv` downloads the currently filtered subset (up to 200 records).
- The Research Toolkit UI now surfaces correlation, distribution, outlier and CSV preview actions.


## Account portals and role-based access

The account routes are separate from the public home page:
- `/admin`: administrator sign-in and protected admin console.
- `/register`: create a standard user account.
- `/login`: user sign-in.
- `/dashboard`: signed-in user's workspace.
- `/forgot-password`: mobile-number OTP recovery demo.

### Required environment configuration

Configure these in the hosting provider's environment settings:
- `PSN_ADMIN_EMAIL`: initial administrator email.
- `PSN_ADMIN_PASSWORD`: strong initial administrator password (never commit it).
- `PSN_SESSION_SECRET`: long, random secret used to sign OTP digests.
- `PSN_DEMO_OTP=true`: enables demo recovery codes for presentations/local testing. The code is shown in the response/UI and **does not send an SMS**. Leave this disabled for production.
- `PSN_ADMIN_MOBILE` (optional): administrator mobile number in international format; default placeholder is for demo use only.

Passwords are salted PBKDF2-HMAC-SHA256 hashes; session identifiers are stored as hashes in an HttpOnly cookie-backed session table; user routes and admin APIs check roles server-side. Admin accounts are provisioned from environment variables and are not created through public registration.

### Important deployment limitation

The current auth store uses SQLite, matching the existing application. Local development persists to `psn.db`, but Vercel's `/tmp` filesystem is ephemeral and cannot serve as a durable production user database. Before relying on registered accounts in production, migrate these auth tables to a managed persistent database (for example, the MongoDB Atlas setup you selected) and wire a real SMS provider for OTP delivery. Do not treat demo OTP as identity verification. User dashboard metrics are currently honest placeholders until existing assessments, follow-ups, and saved analyses are linked to account ownership.
