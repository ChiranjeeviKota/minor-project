from datetime import date
import csv, io
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import Patient, Visit
from .network import DOMAINS, similarity, cognitive_network, clusters, ml, graph_features

Base.metadata.create_all(bind=engine)
app=FastAPI(title="Patient Similarity Network API",version="1.0.0",description="Research prototype using cognitive-domain similarity.")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
class PatientIn(BaseModel):
    patient_code:str
    age:int=Field(ge=18,le=120)
    sex:str
    diagnosis:str
    mmse:float=Field(ge=0,le=30)
    moca:float=Field(ge=0,le=30)
    memory:float=Field(ge=0,le=100)
    attention:float=Field(ge=0,le=100)
    executive:float=Field(ge=0,le=100)
    language:float=Field(ge=0,le=100)
    visuospatial:float=Field(ge=0,le=100)
    processing_speed:float=Field(ge=0,le=100)
    orientation:float=Field(ge=0,le=100)
def patient_json(p):
    return {"id":p.id,"patient_code":p.patient_code,"age":p.age,"sex":p.sex,"diagnosis":p.diagnosis,"mmse":p.mmse,"moca":p.moca,"visit":p.visit,"visit_date":p.visit_date.isoformat() if p.visit_date else None,**{d:getattr(p,d) for d in DOMAINS}}
@app.get("/api/health")
def health(): return {"status":"ok","project":"Patient Similarity Network"}
@app.post("/api/login")
def login(payload:dict):
    if payload.get("username")=="demo" and payload.get("password")=="demo": return {"token":"demo-session","username":"demo"}
    raise HTTPException(401,"Use demo / demo for this prototype.")
@app.get("/api/patients")
def list_patients(db:Session=Depends(get_db),q:str|None=None,diagnosis:str|None=None):
    query=db.query(Patient)
    if q: query=query.filter(Patient.patient_code.contains(q))
    if diagnosis and diagnosis!="All": query=query.filter(Patient.diagnosis==diagnosis)
    return [patient_json(p) for p in query.order_by(Patient.id).all()]
@app.post("/api/patients")
def add_patient(data:PatientIn,db:Session=Depends(get_db)):
    if db.query(Patient).filter_by(patient_code=data.patient_code).first(): raise HTTPException(409,"Patient code already exists.")
    p=Patient(**data.model_dump(),visit=1,visit_date=date.today()); db.add(p); db.commit(); db.refresh(p); return patient_json(p)
@app.get("/api/patients/{pid}")
def get_patient(pid:int,db:Session=Depends(get_db)):
    p=db.get(Patient,pid)
    if not p: raise HTTPException(404,"Patient not found")
    return patient_json(p)
@app.get("/api/patients/{pid}/similar")
def similar_patients(pid:int,method:str="combined",db:Session=Depends(get_db)):
    p=db.get(Patient,pid)
    if not p: raise HTTPException(404,"Patient not found")
    items=[]
    for other in db.query(Patient).filter(Patient.id!=pid).all():
        items.append({**patient_json(other),"similarity":round(similarity(p,other,method),2)})
    return sorted(items,key=lambda x:x["similarity"],reverse=True)[:10]
@app.get("/api/patients/{pid}/cognitive-network")
def patient_network(pid:int,db:Session=Depends(get_db)):
    p=db.get(Patient,pid)
    if not p: raise HTTPException(404,"Patient not found")
    return {**cognitive_network(p),"features":graph_features(p)}
@app.get("/api/patients/{pid}/visits")
def patient_visits(pid:int,db:Session=Depends(get_db)):
    p=db.get(Patient,pid)
    if not p: raise HTTPException(404,"Patient not found")
    return [{"visit":v.visit,"visit_date":v.visit_date.isoformat(),"mmse":v.mmse,"moca":v.moca,**{d:getattr(v,d) for d in DOMAINS}} for v in sorted(p.visits,key=lambda x:x.visit)]
@app.post("/api/patients/{pid}/visits")
def add_visit(pid:int,payload:dict,db:Session=Depends(get_db)):
    p=db.get(Patient,pid)
    if not p: raise HTTPException(404,"Patient not found")
    vals={d:float(payload.get(d,getattr(p,d))) for d in DOMAINS}
    v=Visit(patient_id=pid,visit=max([x.visit for x in p.visits],default=0)+1,visit_date=date.fromisoformat(payload.get("visit_date",date.today().isoformat())),mmse=float(payload.get("mmse",p.mmse)),moca=float(payload.get("moca",p.moca)),**vals)
    db.add(v); db.commit(); return {"status":"created","visit":v.visit}
@app.get("/api/network")
def network(db:Session=Depends(get_db)):
    ps=db.query(Patient).all(); nodes=[{"id":p.id,"label":p.patient_code,"diagnosis":p.diagnosis,"age":p.age} for p in ps]; edges=[]
    for i,p in enumerate(ps):
        for other in ps[i+1:]:
            score=similarity(p,other,"combined")
            if score>=85: edges.append({"source":p.id,"target":other.id,"weight":round(score,1)})
    return {"nodes":nodes,"edges":edges}
@app.get("/api/clusters")
def get_clusters(db:Session=Depends(get_db)): return clusters(db.query(Patient).all())
@app.get("/api/research")
def research(db:Session=Depends(get_db)):
    ps=db.query(Patient).all()
    if len(ps)<12: return {"message":"Add more patients to calculate research metrics.","count":len(ps)}
    return {"count":len(ps),"clustering":clusters(ps),"model":ml(ps)}
@app.get("/api/stats")
def stats(db:Session=Depends(get_db)):
    ps=db.query(Patient).all()
    return {"total":len(ps),"healthy":sum(p.diagnosis=="Healthy" for p in ps),"mci":sum(p.diagnosis=="MCI" for p in ps),"alzheimers":sum(p.diagnosis=="Alzheimer's" for p in ps),"mean_mmse":round(sum(p.mmse for p in ps)/len(ps),1) if ps else 0}
@app.get("/api/export-csv")
def export_csv(db:Session=Depends(get_db)):
    out=io.StringIO(); fields=["patient_code","age","sex","diagnosis","mmse","moca"]+DOMAINS; w=csv.DictWriter(out,fieldnames=fields); w.writeheader()
    for p in db.query(Patient).all(): w.writerow({k:getattr(p,k) for k in fields})
    from fastapi.responses import StreamingResponse
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=patients.csv"})
@app.post("/api/import-csv")
async def import_csv(file:UploadFile=File(...),db:Session=Depends(get_db)):
    raw=(await file.read()).decode("utf-8-sig"); reader=csv.DictReader(io.StringIO(raw)); added=0
    for row in reader:
        code=row.get("patient_code","").strip()
        if not code or db.query(Patient).filter_by(patient_code=code).first(): continue
        try:
            vals={d:float(row[d]) for d in DOMAINS}
            p=Patient(patient_code=code,age=int(row["age"]),sex=row.get("sex","Unknown"),diagnosis=row.get("diagnosis","MCI"),mmse=float(row["mmse"]),moca=float(row["moca"]),visit=1,visit_date=date.today(),**vals)
            db.add(p); added+=1
        except (KeyError,ValueError): continue
    db.commit(); return {"added":added}
