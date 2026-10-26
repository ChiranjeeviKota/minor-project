from datetime import date
import random
from app.database import Base, engine, SessionLocal
from app.models import Patient, Visit

random.seed(42)
Base.metadata.create_all(bind=engine)
db=SessionLocal()
db.query(Visit).delete(); db.query(Patient).delete()
profiles={"Healthy":[78,78,80,80,78,78,82],"MCI":[58,60,55,64,62,57,70],"Alzheimer's":[38,42,35,48,45,40,52]}
domains=["memory","attention","executive","language","visuospatial","processing_speed","orientation"]
n=100
for diagnosis, profile in profiles.items():
    for _ in range(15):
        n+=1
        vals=[max(0,min(100,v+random.gauss(0,6))) for v in profile]
        p=Patient(patient_code=f"P{n}",age=random.randint(60,85),sex=random.choice(["Female","Male"]),diagnosis=diagnosis,
          mmse=round(15+vals[0]*.12,1),moca=round(12+vals[0]*.14,1),visit=1,visit_date=date(2025,1,1),
          **{d:round(v,1) for d,v in zip(domains,vals)})
        db.add(p); db.flush()
        for visit in range(1,4):
            drift=(visit-1)*random.uniform(-2.5,1) if diagnosis!="Healthy" else random.uniform(-1,1)
            vv=[max(0,min(100,v+drift+random.gauss(0,2))) for v in vals]
            db.add(Visit(patient_id=p.id,visit=visit,visit_date=date(2025+visit-1,1,1),
              mmse=round(15+vv[0]*.12,1),moca=round(12+vv[0]*.14,1),**{d:round(v,1) for d,v in zip(domains,vv)}))
db.commit(); db.close()
print("Created 45 synthetic patients and 3 visits each.")
