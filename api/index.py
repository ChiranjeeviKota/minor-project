"""Vercel serverless entry point for the FastAPI application."""
from backend.app.main import app

# Vercel's filesystem is ephemeral. Demo records are initialized in the
# writable /tmp SQLite database for each warm serverless instance if empty.
from backend.app.database import SessionLocal
from backend.app.models import Patient, Visit
from datetime import date
import random


def ensure_demo_data():
    db = SessionLocal()
    try:
        if db.query(Patient).count():
            return
        random.seed(42)
        profiles = {
            "Healthy": [78, 78, 80, 80, 78, 78, 82],
            "MCI": [58, 60, 55, 64, 62, 57, 70],
            "Alzheimer's": [38, 42, 35, 48, 45, 40, 52],
        }
        domains = ["memory", "attention", "executive", "language", "visuospatial", "processing_speed", "orientation"]
        n = 100
        for diagnosis, profile in profiles.items():
            for _ in range(15):
                n += 1
                vals = [max(0, min(100, v + random.gauss(0, 6))) for v in profile]
                patient = Patient(
                    patient_code=f"P{n}", age=random.randint(60, 85),
                    sex=random.choice(["Female", "Male"]), diagnosis=diagnosis,
                    mmse=round(15 + vals[0] * .12, 1), moca=round(12 + vals[0] * .14, 1),
                    visit=1, visit_date=date(2025, 1, 1),
                    **{d: round(v, 1) for d, v in zip(domains, vals)},
                )
                db.add(patient)
                db.flush()
                for visit_no in range(1, 4):
                    drift = (visit_no - 1) * random.uniform(-2.5, 1) if diagnosis != "Healthy" else random.uniform(-1, 1)
                    vv = [max(0, min(100, v + drift + random.gauss(0, 2))) for v in vals]
                    db.add(Visit(
                        patient_id=patient.id, visit=visit_no,
                        visit_date=date(2025 + visit_no - 1, 1, 1),
                        mmse=round(15 + vv[0] * .12, 1), moca=round(12 + vv[0] * .14, 1),
                        **{d: round(v, 1) for d, v in zip(domains, vv)},
                    ))
        db.commit()
    finally:
        db.close()


ensure_demo_data()
