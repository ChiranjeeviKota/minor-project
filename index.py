# Patient Similarity Network: single-file FastAPI backend + embedded frontend.
# Academic demo only. All initial records are synthetic; not for clinical decisions.
# Local run: pip install -r requirements.txt && uvicorn index:app --reload
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
import sqlite3, os, csv, io, random, math
from datetime import date

DB_PATH = os.getenv("DATABASE_PATH", "/tmp/psn.db" if os.getenv("VERCEL") else "psn.db")
DOMAINS = ["memory", "attention", "executive", "language", "visuospatial", "processing_speed", "orientation"]
app = FastAPI(title="Patient Similarity Network", version="2.0.0")

def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = connect()
    db.execute("""CREATE TABLE IF NOT EXISTS patients (
      id INTEGER PRIMARY KEY AUTOINCREMENT, patient_code TEXT UNIQUE NOT NULL,
      age INTEGER NOT NULL, sex TEXT NOT NULL, diagnosis TEXT NOT NULL,
      mmse REAL NOT NULL, moca REAL NOT NULL, visit INTEGER DEFAULT 1,
      visit_date TEXT, memory REAL NOT NULL, attention REAL NOT NULL,
      executive REAL NOT NULL, language REAL NOT NULL, visuospatial REAL NOT NULL,
      processing_speed REAL NOT NULL, orientation REAL NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS visits (
      id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
      visit_date TEXT NOT NULL, mmse REAL NOT NULL, moca REAL NOT NULL,
      memory REAL NOT NULL, attention REAL NOT NULL, executive REAL NOT NULL,
      language REAL NOT NULL, visuospatial REAL NOT NULL, processing_speed REAL NOT NULL,
      orientation REAL NOT NULL, FOREIGN KEY(patient_id) REFERENCES patients(id))""")
    if db.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0:
        rng = random.Random(42)
        profiles = {"Healthy":[78,78,80,80,78,78,82], "MCI":[58,60,55,64,62,57,70], "Alzheimer's":[38,42,35,48,45,40,52]}
        n = 100
        for diagnosis, profile in profiles.items():
            for _ in range(15):
                n += 1
                vals = [round(max(0,min(100,v+rng.gauss(0,6))),1) for v in profile]
                row = {"patient_code":f"P{n}","age":rng.randint(60,85),"sex":rng.choice(["Female","Male"]),"diagnosis":diagnosis,"mmse":round(15+vals[0]*.12,1),"moca":round(12+vals[0]*.14,1),"visit":1,"visit_date":"2025-01-01"}
                row.update(dict(zip(DOMAINS, vals)))
                cols = list(row)
                db.execute(f"INSERT INTO patients ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})", [row[k] for k in cols])
        db.commit()
    db.close()
init_db()

def all_patients():
    db=connect()
    rows=db.execute("SELECT * FROM patients ORDER BY id").fetchall()
    db.close()
    return [dict(r) for r in rows]

def similarity(a,b,method="weighted"):
    av=[float(a[d]) for d in DOMAINS]; bv=[float(b[d]) for d in DOMAINS]
    if method=="euclidean":
        distance=math.sqrt(sum((x-y)**2 for x,y in zip(av,bv))/len(DOMAINS))
        return round(max(0,100-distance),1)
    if method=="cosine":
        dot=sum(x*y for x,y in zip(av,bv)); na=math.sqrt(sum(x*x for x in av)); nb=math.sqrt(sum(y*y for y in bv))
        return round(max(0,min(100,100*(dot/(na*nb) if na and nb else 0))),1)
    weights=[.22,.14,.18,.12,.12,.10,.12]
    distance=sum(w*abs(x-y) for w,x,y in zip(weights,av,bv))
    return round(max(0,min(100,100-distance)),1)

class PatientIn(BaseModel):
    patient_code: str = Field(min_length=1, max_length=40)
    age: int = Field(ge=18, le=120)
    sex: str = "Unknown"
    diagnosis: str
    mmse: float = Field(ge=0, le=30)
    moca: float = Field(ge=0, le=30)
    memory: float = Field(ge=0, le=100)
    attention: float = Field(ge=0, le=100)
    executive: float = Field(ge=0, le=100)
    language: float = Field(ge=0, le=100)
    visuospatial: float = Field(ge=0, le=100)
    processing_speed: float = Field(ge=0, le=100)
    orientation: float = Field(ge=0, le=100)

@app.get("/api/health")
def health(): return {"status":"ok","project":"Patient Similarity Network"}
@app.get("/api/patients")
def list_patients(q: str|None=None, diagnosis: str|None=None):
    return [p for p in all_patients() if (not q or q.lower() in p["patient_code"].lower()) and (not diagnosis or diagnosis=="All" or p["diagnosis"]==diagnosis)]
@app.post("/api/patients")
def add_patient(p: PatientIn):
    data=p.model_dump()
    data.update(visit=1,visit_date=date.today().isoformat())
    db=connect()
    try:
        cols=list(data)
        db.execute(f"INSERT INTO patients ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",[data[k] for k in cols])
        db.commit()
        return dict(db.execute("SELECT * FROM patients WHERE patient_code=?",(p.patient_code,)).fetchone())
    except sqlite3.IntegrityError:
        raise HTTPException(409,"Patient code already exists.")
    finally: db.close()
@app.get("/api/patients/{pid}/similar")
def similar_patients(pid:int, method:str="weighted", threshold:float=0):
    if method not in ("weighted","cosine","euclidean"): raise HTTPException(400,"Unknown similarity method")
    if not 0<=threshold<=100: raise HTTPException(400,"Threshold must be between 0 and 100")
    ps=all_patients()
    target=next((p for p in ps if p["id"]==pid),None)
    if not target: raise HTTPException(404,"Patient not found")
    results=[{**p,"similarity":similarity(target,p,method)} for p in ps if p["id"]!=pid]
    return [p for p in sorted(results,key=lambda p:p["similarity"],reverse=True) if p["similarity"]>=threshold][:10]
@app.get("/api/patients/{pid}/cognitive-network")
def patient_network(pid:int):
    p=next((p for p in all_patients() if p["id"]==pid),None)
    if not p: raise HTTPException(404,"Patient not found")
    return {"nodes":[{"id":d,"value":p[d]} for d in DOMAINS],
      "edges":[{"source":DOMAINS[i],"target":DOMAINS[j],"weight":round(100-abs(p[DOMAINS[i]]-p[DOMAINS[j]]),1)} for i in range(len(DOMAINS)) for j in range(i+1,len(DOMAINS))]}
@app.get("/api/network")
def network():
    ps=all_patients(); nodes=[{"id":p["id"],"label":p["patient_code"],"diagnosis":p["diagnosis"],"age":p["age"]} for p in ps]; edges=[]
    for i,p in enumerate(ps):
        for other in ps[i+1:]:
            score=similarity(p,other)
            if score>=85: edges.append({"source":p["id"],"target":other["id"],"weight":score})
    return {"nodes":nodes,"edges":edges}
@app.get("/api/clusters")
def clusters(k:int=3):
    ps=all_patients()
    if not ps: return {"clusters":[],"k":k,"silhouette":0}
    k=max(2,min(int(k),min(6,len(ps))))
    vectors=[[float(p[d]) for d in DOMAINS] for p in ps]
    centers=[vectors[round(i*(len(vectors)-1)/(k-1))][:] for i in range(k)]
    labels=[-1]*len(vectors)
    for _ in range(20):
        next_labels=[min(range(k),key=lambda j:sum((x-y)**2 for x,y in zip(v,centers[j]))) for v in vectors]
        new_centers=[]
        for j in range(k):
            group=[v for v,l in zip(vectors,next_labels) if l==j]
            new_centers.append([sum(v[d] for v in group)/len(group) for d in range(len(DOMAINS))] if group else centers[j])
        if next_labels==labels: labels=next_labels; centers=new_centers; break
        labels,centers=next_labels,new_centers
    counts={str(j):labels.count(j) for j in range(k)}
    return {"k":k,"clusters":[{"patient_id":p["id"],"patient_code":p["patient_code"],"cluster":labels[i]} for i,p in enumerate(ps)],"sizes":counts,"method":"K-means on seven cognitive domains","note":"Exploratory unsupervised clustering; not clinically validated."}
@app.get("/api/evaluation")
def evaluation():
    ps=all_patients()
    if len(ps)<2: return {"patients":len(ps),"silhouette":None,"ari":None,"note":"At least two records are needed."}
    labels={x["patient_id"]:x["cluster"] for x in clusters(3)["clusters"]}
    vectors={p["id"]:[float(p[d]) for d in DOMAINS] for p in ps}
    def dist(a,b): return math.sqrt(sum((x-y)**2 for x,y in zip(a,b))/len(DOMAINS))
    vals=[]
    for p in ps[:min(len(ps),100)]:
        same=[q for q in ps if q["id"]!=p["id"] and labels[q["id"]]==labels[p["id"]]]
        other=[q for q in ps if labels[q["id"]]!=labels[p["id"]]]
        if not same or not other: continue
        a=sum(dist(vectors[p["id"]],vectors[q["id"]]) for q in same)/len(same)
        other_clusters=set(labels[q["id"]] for q in other)
        b=min(sum(dist(vectors[p["id"]],vectors[q["id"]]) for q in other if labels[q["id"]]==c)/sum(1 for q in other if labels[q["id"]]==c) for c in other_clusters)
        vals.append((b-a)/max(a,b) if max(a,b)>0 else 0)
    return {"patients":len(ps),"silhouette":round(sum(vals)/len(vals),3) if vals else None,"ari":None,"ari_note":"ARI requires independent reference labels; not reported as ground truth here.","note":"Silhouette is an internal clustering metric on synthetic demo data."}
@app.get("/api/feature-importance")
def feature_importance():
    weights={"memory":.22,"attention":.14,"executive":.18,"language":.12,"visuospatial":.12,"processing_speed":.10,"orientation":.12}
    return {"features":[{"feature":k,"weight":v,"percent":round(v*100,1)} for k,v in sorted(weights.items(),key=lambda x:x[1],reverse=True)],"method":"Preset weighted-distance contribution, not trained-model feature importance."}
@app.get("/api/graph-features")
def graph_features(threshold:float=85):
    ps=all_patients(); edges=[]
    for i,p in enumerate(ps):
        for q in ps[i+1:]:
            score=similarity(p,q)
            if score>=threshold: edges.append((p["id"],q["id"],score))
    degree={p["id"]:0 for p in ps}
    for a,b,_ in edges: degree[a]+=1; degree[b]+=1
    return {"threshold":threshold,"nodes":len(ps),"edges":len(edges),"density":round(2*len(edges)/(len(ps)*(len(ps)-1)),4) if len(ps)>1 else 0,"average_degree":round(sum(degree.values())/len(ps),2) if ps else 0,"top_degree":[{"patient_id":p["id"],"patient_code":p["patient_code"],"degree":degree[p["id"]]} for p in sorted(ps,key=lambda p:degree[p["id"]],reverse=True)[:10]],"note":"Graph metrics use thresholded weighted similarity."}
class VisitIn(BaseModel):
    visit_date: str
    mmse: float = Field(ge=0,le=30)
    moca: float = Field(ge=0,le=30)
    memory: float = Field(ge=0,le=100)
    attention: float = Field(ge=0,le=100)
    executive: float = Field(ge=0,le=100)
    language: float = Field(ge=0,le=100)
    visuospatial: float = Field(ge=0,le=100)
    processing_speed: float = Field(ge=0,le=100)
    orientation: float = Field(ge=0,le=100)
@app.get("/api/patients/{pid}/visits")
def get_visits(pid:int):
    db=connect()
    patient=db.execute("SELECT id,patient_code,mmse,moca,visit_date,"+",".join(DOMAINS)+" FROM patients WHERE id=?",(pid,)).fetchone()
    if not patient: db.close(); raise HTTPException(404,"Patient not found")
    rows=db.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY visit_date,id",(pid,)).fetchall()
    if not rows:
        base=dict(patient)
        db.execute("INSERT INTO visits (patient_id,visit_date,mmse,moca,"+",".join(DOMAINS)+") VALUES ("+",".join("?" for _ in range(11))+")",[pid,base.get("visit_date") or date.today().isoformat(),base["mmse"],base["moca"]]+[base[d] for d in DOMAINS])
        db.commit(); rows=db.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY visit_date,id",(pid,)).fetchall()
    db.close()
    return {"patient_id":pid,"patient_code":patient["patient_code"],"visits":[dict(r) for r in rows]}
@app.post("/api/patients/{pid}/visits")
def add_visit(pid:int,v:VisitIn):
    db=connect()
    if not db.execute("SELECT id FROM patients WHERE id=?",(pid,)).fetchone(): db.close(); raise HTTPException(404,"Patient not found")
    data=v.model_dump(); cols=["patient_id"]+list(data)
    try:
        db.execute("INSERT INTO visits ("+",".join(cols)+") VALUES ("+",".join("?" for _ in cols)+")",[pid]+[data[k] for k in data])
        db.execute("UPDATE patients SET visit=visit+1,visit_date=? WHERE id=?",(v.visit_date,pid))
        db.commit()
    except sqlite3.Error as e:
        db.close(); raise HTTPException(400,str(e))
    rows=db.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY visit_date,id",(pid,)).fetchall()
    db.close()
    return {"status":"ok","visits":[dict(r) for r in rows]}
@app.get("/api/research")
def research(): return {"count":len(all_patients()),"message":"Exploratory metrics on synthetic data; not a trained clinical model."}
@app.get("/api/stats")
def stats():
    ps=all_patients(); n=len(ps)
    return {"total":n,"healthy":sum(p["diagnosis"]=="Healthy" for p in ps),"mci":sum(p["diagnosis"]=="MCI" for p in ps),"alzheimers":sum(p["diagnosis"]=="Alzheimer's" for p in ps),"mean_mmse":round(sum(p["mmse"] for p in ps)/n,1) if n else 0}
@app.get("/api/export-csv")
def export_csv():
    ps=all_patients(); out=io.StringIO(); fields=["patient_code","age","sex","diagnosis","mmse","moca"]+DOMAINS
    w=csv.DictWriter(out,fieldnames=fields); w.writeheader(); w.writerows([{k:p[k] for k in fields} for p in ps])
    return Response(out.getvalue(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=patients.csv"})
@app.post("/api/import-csv")
async def import_csv(file:UploadFile=File(...)):
    try: rows=csv.DictReader(io.StringIO((await file.read()).decode("utf-8-sig")))
    except Exception: raise HTTPException(400,"Could not read CSV")
    added=0; db=connect()
    for row in rows:
        try:
            data={"patient_code":row["patient_code"].strip(),"age":int(row["age"]),"sex":row.get("sex","Unknown"),"diagnosis":row.get("diagnosis","MCI"),"mmse":float(row["mmse"]),"moca":float(row["moca"]),"visit":1,"visit_date":date.today().isoformat()}
            data.update({d:float(row[d]) for d in DOMAINS})
            cols=list(data); db.execute(f"INSERT INTO patients ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",[data[k] for k in cols]); added+=1
        except (KeyError,ValueError,sqlite3.IntegrityError): continue
    db.commit(); db.close()
    return {"added":added}

HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Patient Similarity Network</title><style>
:root{color-scheme:dark;--bg:#0b1020;--line:#263650;--muted:#9eabc2;--text:#edf3ff;--mint:#7dd3b0;--blue:#8ea9ff;--gold:#f3c47a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#15233a,var(--bg) 58%);font:14px/1.5 system-ui,sans-serif;color:var(--text)}main{max-width:1150px;margin:auto;padding:24px}header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center}h1{margin:0;font-size:28px}h2{font-size:17px}.muted,small{color:var(--muted)}.notice{padding:12px;border:1px solid #55472b;background:#28251d;color:#ead9ad;border-radius:12px;margin:16px 0}.nav,.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}button,.btn,select,input{border:1px solid var(--line);background:#172238;color:var(--text);border-radius:8px;padding:10px;cursor:pointer}button.active,.primary{background:#b9f3dd;color:#10271f;font-weight:bold}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}.card,section{background:#121b2e;border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px}.card strong{display:block;font-size:28px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:560px}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted)}.hidden{display:none}.metric{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)}.bar{height:7px;background:#28354b;margin:5px 0 10px;border-radius:9px;overflow:hidden}.bar span{display:block;height:100%;background:var(--blue)}.patientgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.patient{display:flex;flex-direction:column;align-items:flex-start;width:100%}@media(max-width:750px){.cards{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}.patientgrid{grid-template-columns:repeat(2,1fr)}}@media(max-width:450px){.patientgrid{grid-template-columns:1fr}main{padding:12px}}
</style></head><body><main><header><div><h1>Patient Similarity Network</h1><div class="muted">Cognitive networks · Alzheimer’s research prototype</div></div><b style="color:var(--mint)">● API-POWERED DEMO</b></header><div class="notice">Academic research demo only. Records shown by default are synthetic. Not clinically validated; do not use for diagnosis or treatment decisions.</div><nav class="nav"><button class="active" data-tab="overview">Overview</button><button data-tab="network">Patient Network</button><button data-tab="patients">Patient Explorer</button><button data-tab="analytics">Phase 2 Analytics</button><button data-tab="longitudinal">Phase 3 Follow-ups</button><button data-tab="research">Research Lab</button></nav><div id="error" class="notice hidden"></div><div id="overview"><div class="cards" id="stats"></div><div class="two"><section><h2>Cohort distribution</h2><div id="distribution"></div></section><section><h2>Quick actions</h2><p class="muted">Explore profiles, compare cognitive-domain similarity, inspect network relationships and export records.</p><button class="primary" onclick="tab('patients')">Explore patients</button> <button onclick="load()">Refresh</button> <button onclick="location.href='/api/export-csv'">Export CSV</button><p id="mean" class="muted"></p></section></div></div><div id="network" class="hidden"><section><h2>Patient similarity network</h2><p class="muted">Each node is a patient; lines connect profiles with high cognitive similarity. Click a node to open its profile.</p><div class="toolbar"><button onclick="drawNetwork()">Refresh network</button><span class="muted">Green = Healthy · Blue = MCI · Gold = Alzheimer's</span></div><div style="width:100%;overflow:auto"><svg id="networkGraph" viewBox="0 0 900 500" role="img" aria-label="Interactive patient similarity network" style="display:block;width:100%;min-width:600px;height:auto;border-radius:10px;background:#0d1525"></svg></div><div id="networkgrid" class="patientgrid" style="margin-top:12px"></div></section></div>
<div id="patients" class="hidden"><section><h2>Phase 1 · Register a patient</h2><p class="muted">Add an assessment profile with MMSE, MoCA and seven cognitive-domain scores.</p><form id="patientForm" onsubmit="addPatient(event)"><div class="toolbar"><input name="patient_code" required maxlength="40" placeholder="Patient code (e.g. P201)"><input name="age" type="number" min="18" max="120" required value="65" style="width:95px"><select name="sex"><option>Female</option><option>Male</option><option>Other</option><option>Unknown</option></select><select name="diagnosis"><option>Healthy</option><option selected>MCI</option><option>Alzheimer's</option></select><input name="mmse" type="number" min="0" max="30" step="0.1" required value="24" placeholder="MMSE" style="width:95px"><input name="moca" type="number" min="0" max="30" step="0.1" required value="20" placeholder="MoCA" style="width:95px"></div><div class="toolbar"><label>Memory <input name="memory" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Attention <input name="attention" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Executive <input name="executive" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Language <input name="language" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Visuospatial <input name="visuospatial" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Processing speed <input name="processing_speed" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Orientation <input name="orientation" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label></div><button class="primary" type="submit">Register patient</button> <span id="formStatus" class="muted" role="status"></span></form></section><section><h2>Patient explorer</h2><div class="toolbar"><input id="q" placeholder="Search patient code" oninput="renderPatients()"><select id="filter" onchange="renderPatients()"><option>All</option><option>Healthy</option><option>MCI</option><option>Alzheimer's</option></select><button onclick="location.href='/api/export-csv'">Export CSV</button><label class="btn">Import CSV<input type="file" accept=".csv" hidden onchange="importFile(this)"></label></div><div class="tablewrap"><table><thead><tr><th>Patient</th><th>Age</th><th>Diagnosis</th><th>MMSE</th><th>MoCA</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></section><div class="two"><section><h2>Selected profile</h2><div id="profile" class="muted">Choose Compare on a patient.</div></section><section><h2>Closest similar patients</h2><div id="similar" class="muted">Choose a patient to compare.</div></section></div></div>
<div id="analytics" class="hidden"><section><h2>Phase 2 · Similarity analysis</h2><p class="muted">Compare cognitive profiles using multiple methods and adjust the minimum score.</p><div class="toolbar"><label>Patient <select id="analysisPatient"></select></label><label>Method <select id="simMethod"><option value="weighted">Weighted distance</option><option value="cosine">Cosine similarity</option><option value="euclidean">Euclidean similarity</option></select></label><label>Minimum score <input id="simThreshold" type="number" min="0" max="100" value="75" style="width:90px"></label><button class="primary" onclick="runSimilarity()">Compare profiles</button></div><div id="similarityResults" class="muted">Choose settings and run a comparison.</div></section><div class="two"><section><h2>K-means clustering</h2><div class="toolbar"><label>Clusters <select id="clusterCount"><option>2</option><option selected>3</option><option>4</option><option>5</option></select></label><button onclick="runClusters()">Run clustering</button></div><div id="clusterResults" class="muted"></div></section><section><h2>Evaluation metrics</h2><button onclick="runPhase2()">Calculate metrics</button><div id="evaluationResults" class="muted" style="margin-top:10px"></div></section></div><section><h2>Domain feature contribution</h2><div id="featureImportance" class="muted">Run evaluation to view weighted contributions.</div></section><section><h2>Graph statistics</h2><div class="toolbar"><label>Edge threshold <input id="graphThreshold" type="number" min="0" max="100" value="85" style="width:90px"></label><button onclick="runGraphFeatures()">Calculate graph features</button></div><div id="graphResults" class="muted"></div></section></div>
<div id="longitudinal" class="hidden"><section><h2>Phase 3 · Longitudinal cognitive visits</h2><p class="muted">Record follow-up assessments and review changes over time.</p><form id="visitForm" onsubmit="addVisit(event)"><div class="toolbar"><label>Patient <select id="visitPatient" name="patient_id" required onchange="loadVisits()"></select></label><label>Visit date <input name="visit_date" type="date" required></label><label>MMSE <input name="mmse" type="number" min="0" max="30" step="0.1" value="24" required style="width:85px"></label><label>MoCA <input name="moca" type="number" min="0" max="30" step="0.1" value="20" required style="width:85px"></label></div><div class="toolbar"><label>Memory <input name="memory" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Attention <input name="attention" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Executive <input name="executive" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Language <input name="language" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Visuospatial <input name="visuospatial" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Processing speed <input name="processing_speed" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Orientation <input name="orientation" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label></div><button class="primary" type="submit">Save follow-up visit</button> <span id="visitStatus" class="muted" role="status"></span></form></section><section><h2>Visit history and progression</h2><div id="visitHistory" class="muted">Select a patient to load visit history.</div><div id="progression" style="margin-top:12px"></div></section><section><h2>Cognitive-domain network</h2><p class="muted">Explore the patient similarity network and graph statistics.</p><button onclick="tab('network')">Open patient network</button></section></div>
<div id="research" class="hidden"><div class="cards" id="researchcards"></div><section><h2>Research summary</h2><p class="muted">Exploratory metrics on synthetic demo records; not clinical evidence.</p><div id="researchtext"></div><button onclick="load()">Refresh summary</button> <button onclick="runPhase2()">Run evaluation</button><div id="researchSummary" style="margin-top:12px"></div></section></div><div id="analytics" class="hidden"><section><h2>Phase 2 · Similarity analysis</h2><p class="muted">Compare profiles with weighted, cosine or Euclidean similarity and tune the match threshold.</p><div class="toolbar"><label>Patient <select id="analysisPatient"></select></label><label>Method <select id="simMethod"><option value="weighted">Weighted distance</option><option value="cosine">Cosine similarity</option><option value="euclidean">Euclidean similarity</option></select></label><label>Minimum score <input id="simThreshold" type="number" min="0" max="100" value="75" style="width:90px"></label><button class="primary" onclick="runSimilarity()">Compare profiles</button></div><div id="similarityResults" class="muted">Choose settings and run a comparison.</div></section><div class="two"><section><h2>K-means clustering</h2><p class="muted">Group cognitive profiles without using diagnosis labels.</p><div class="toolbar"><label>Clusters <select id="clusterCount"><option>2</option><option selected>3</option><option>4</option><option>5</option></select></label><button onclick="runClusters()">Run clustering</button></div><div id="clusterResults" class="muted"></div></section><section><h2>Evaluation metrics</h2><button onclick="runPhase2()">Calculate metrics</button><div id="evaluationResults" class="muted" style="margin-top:10px"></div></section></div><section><h2>Domain feature contribution</h2><div id="featureImportance" class="muted">Run evaluation to view weighted contributions.</div></section><section><h2>Graph statistics</h2><div class="toolbar"><label>Edge threshold <input id="graphThreshold" type="number" min="0" max="100" value="85" style="width:90px"></label><button onclick="runGraphFeatures()">Calculate graph features</button></div><div id="graphResults" class="muted"></div></section></div><div id="longitudinal" class="hidden"><section><h2>Phase 3 · Longitudinal cognitive visits</h2><p class="muted">Record follow-up assessments for the same patient and review score trends over time.</p><form id="visitForm" onsubmit="addVisit(event)"><div class="toolbar"><label>Patient <select id="visitPatient" name="patient_id" required onchange="loadVisits()"></select></label><label>Visit date <input name="visit_date" type="date" required></label><label>MMSE <input name="mmse" type="number" min="0" max="30" step="0.1" value="24" required style="width:85px"></label><label>MoCA <input name="moca" type="number" min="0" max="30" step="0.1" value="20" required style="width:85px"></label></div><div class="toolbar"><label>Memory <input name="memory" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Attention <input name="attention" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Executive <input name="executive" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Language <input name="language" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Visuospatial <input name="visuospatial" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Processing speed <input name="processing_speed" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Orientation <input name="orientation" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label></div><button class="primary" type="submit">Save follow-up visit</button> <span id="visitStatus" class="muted" role="status"></span></form></section><section><h2>Visit history and progression</h2><div id="visitHistory" class="muted">Select a patient to load visit history.</div><div id="progression" style="margin-top:12px"></div></section><section><h2>Cognitive-domain network features</h2><p class="muted">The patient network connects profiles above the similarity threshold. Graph statistics are available under Phase 2 Analytics.</p><button onclick="tab(this.dataset.target)" data-target="network">Open patient network</button></section></div></main><script>
let patients=[],stats={};const domains=['memory','attention','executive','language','visuospatial','processing_speed','orientation'];const colors={Healthy:'var(--mint)',MCI:'var(--blue)',"Alzheimer's":'var(--gold)'};
function tab(n){document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===n));['overview','network','patients','analytics','longitudinal','research'].forEach(x=>document.getElementById(x).classList.toggle('hidden',x!==n));if(n==='longitudinal')loadVisits();if(n==='analytics')runPhase2();if(n==='network')drawNetwork()}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>tab(b.dataset.tab));
async function get(u){let r=await fetch(u);if(!r.ok)throw Error((await r.text()).slice(0,150));return r.json()}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){try{document.getElementById('error').classList.add('hidden');[patients,stats]=await Promise.all([get('/api/patients'),get('/api/stats')]);render();refreshPatientSelects()}catch(e){let x=document.getElementById('error');x.textContent='Could not load data: '+e.message;x.classList.remove('hidden')}}
function render(){document.getElementById('stats').innerHTML=[['Total patients',stats.total],['Healthy cohort',stats.healthy],['MCI cohort',stats.mci],["Alzheimer’s cohort",stats.alzheimers]].map(([a,b])=>'<div class="card"><small>'+a+'</small><strong>'+(b??'—')+'</strong><small>Synthetic sample records</small></div>').join('');let total=stats.total||1;document.getElementById('distribution').innerHTML=[['Healthy',stats.healthy],['MCI',stats.mci],["Alzheimer's",stats.alzheimers]].map(([n,v])=>'<div class="metric"><span>'+n+'</span><b>'+v+'</b></div><div class="bar"><span style="width:'+(v/total*100)+'%;background:'+colors[n]+'"></span></div>').join('');document.getElementById('mean').textContent='Mean MMSE: '+stats.mean_mmse+' / 30';document.getElementById('networkgrid').innerHTML=patients.slice(0,30).map(p=>'<button class="patient" onclick="selectPatient('+p.id+')"><b>'+esc(p.patient_code)+'</b><span style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</span><small>Age '+p.age+' · MMSE '+p.mmse+'</small></button>').join('');renderPatients();document.getElementById('researchcards').innerHTML=[['Records',stats.total],['Cohorts',3],['Similarity','Weighted'],['Clinical status','Not validated']].map(([a,b])=>'<div class="card"><small>'+a+'</small><strong style="font-size:21px">'+b+'</strong></div>').join('');document.getElementById('researchtext').textContent='Similarity compares seven cognitive domains. Grouping is a transparent demonstration, not a validated clinical algorithm.'}

function refreshPatientSelects(){['analysisPatient','visitPatient'].forEach(id=>{const el=document.getElementById(id);if(!el)return;const prev=el.value;el.innerHTML=patients.map(p=>'<option value="'+p.id+'">'+esc(p.patient_code)+' · '+esc(p.diagnosis)+'</option>').join('');if(patients.some(p=>String(p.id)===prev))el.value=prev});}
async function runSimilarity(){const id=document.getElementById('analysisPatient').value;if(!id)return;const method=document.getElementById('simMethod').value;const threshold=Math.max(0,Math.min(100,Number(document.getElementById('simThreshold').value)||0));const out=document.getElementById('similarityResults');out.textContent='Calculating...';try{const rows=await get('/api/patients/'+id+'/similar?method='+encodeURIComponent(method)+'&threshold='+threshold);out.innerHTML=rows.length?'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Diagnosis</th><th>Similarity</th></tr></thead><tbody>'+rows.map(p=>'<tr><td>'+esc(p.patient_code)+'</td><td>'+esc(p.diagnosis)+'</td><td>'+p.similarity+'%</td></tr>').join('')+'</tbody></table></div>':'No matches above '+threshold+'%';}catch(e){out.textContent=e.message}}
async function runClusters(){const out=document.getElementById('clusterResults');out.textContent='Clustering...';try{const d=await get('/api/clusters?k='+document.getElementById('clusterCount').value);out.innerHTML='<p>'+d.note+'</p><div class="metric"><span>Records grouped</span><b>'+d.clusters.length+'</b></div>'+Object.entries(d.sizes).map(([k,v])=>'<div class="metric"><span>Cluster '+(Number(k)+1)+'</span><b>'+v+' patients</b></div>').join('')+'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Cluster</th></tr></thead><tbody>'+d.clusters.map(x=>'<tr><td>'+esc(x.patient_code)+'</td><td>'+(x.cluster+1)+'</td></tr>').join('')+'</tbody></table></div>';}catch(e){out.textContent=e.message}}
async function runPhase2(){try{const [ev,fi]=await Promise.all([get('/api/evaluation'),get('/api/feature-importance')]);document.getElementById('evaluationResults').innerHTML='<div class="metric"><span>Records evaluated</span><b>'+ev.patients+'</b></div><div class="metric"><span>Silhouette score</span><b>'+(ev.silhouette===null?'Not available':ev.silhouette)+'</b></div><p class="muted">'+esc(ev.note)+' '+esc(ev.ari_note||'')+'</p>';document.getElementById('featureImportance').innerHTML=fi.features.map(x=>'<div class="metric"><span>'+esc(x.feature.replace('_',' '))+'</span><b>'+x.percent+'%</b></div><div class="bar"><span style="width:'+x.percent+'%"></span></div>').join('')+'<small>'+esc(fi.method)+'</small>';document.getElementById('researchSummary').textContent='Silhouette: '+(ev.silhouette===null?'not available':ev.silhouette)+' · records: '+ev.patients;await runClusters();await runGraphFeatures()}catch(e){document.getElementById('evaluationResults').textContent='Evaluation error: '+e.message}}
async function runGraphFeatures(){const out=document.getElementById('graphResults');try{const threshold=Math.max(0,Math.min(100,Number(document.getElementById('graphThreshold').value)||85));const d=await get('/api/graph-features?threshold='+threshold);out.innerHTML='<div class="metric"><span>Nodes</span><b>'+d.nodes+'</b></div><div class="metric"><span>Edges</span><b>'+d.edges+'</b></div><div class="metric"><span>Network density</span><b>'+d.density+'</b></div><div class="metric"><span>Average degree</span><b>'+d.average_degree+'</b></div><h3>Most connected patients</h3>'+d.top_degree.map(p=>'<div class="metric"><span>'+esc(p.patient_code)+'</span><b>'+p.degree+' connections</b></div>').join('')+'<small>'+esc(d.note)+'</small>'}catch(e){out.textContent=e.message}}
async function loadVisits(){const id=document.getElementById('visitPatient')?.value;if(!id)return;const out=document.getElementById('visitHistory');try{const d=await get('/api/patients/'+id+'/visits');const v=d.visits||[];out.innerHTML='<div class="metric"><span>Patient</span><b>'+esc(d.patient_code)+'</b></div><div class="tablewrap"><table><thead><tr><th>Date</th><th>MMSE</th><th>MoCA</th><th>Mean domain score</th></tr></thead><tbody>'+v.map(x=>'<tr><td>'+esc(x.visit_date)+'</td><td>'+x.mmse+'</td><td>'+x.moca+'</td><td>'+Math.round(domains.reduce((a,k)=>a+Number(x[k]),0)/domains.length*10)/10+'</td></tr>').join('')+'</tbody></table></div>';document.getElementById('progression').innerHTML='<h3>MMSE progression</h3>'+v.map(x=>'<div class="metric"><span>'+esc(x.visit_date)+'</span><b>'+x.mmse+'/30</b></div><div class="bar"><span style="width:'+Math.max(0,Math.min(100,x.mmse/30*100))+'%"></span></div>').join('')}catch(e){out.textContent=e.message}}
async function addVisit(e){e.preventDefault();const form=e.currentTarget;const status=document.getElementById('visitStatus');const data=Object.fromEntries(new FormData(form).entries());const id=data.patient_id;delete data.patient_id;['mmse','moca',...domains].forEach(k=>data[k]=Number(data[k]));status.textContent='Saving...';try{const r=await fetch('/api/patients/'+id+'/visits',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await r.json();if(!r.ok)throw Error(result.detail||'Could not save visit');status.textContent='Follow-up saved';await loadVisits()}catch(err){status.textContent=err.message}}
function renderPatients(){let q=(document.getElementById('q')?.value||'').toLowerCase(),f=document.getElementById('filter')?.value||'All';let list=patients.filter(p=>p.patient_code.toLowerCase().includes(q)&&(f==='All'||p.diagnosis===f));document.getElementById('rows').innerHTML=list.map(p=>'<tr><td>'+esc(p.patient_code)+'</td><td>'+p.age+'</td><td style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</td><td>'+p.mmse+'</td><td>'+p.moca+'</td><td><button onclick="selectPatient('+p.id+')">Compare</button></td></tr>').join('')}
async function addPatient(e){e.preventDefault();const form=e.currentTarget;const status=document.getElementById('formStatus');const data=Object.fromEntries(new FormData(form).entries());['age','mmse','moca',...domains].forEach(k=>data[k]=Number(data[k]));status.textContent='Saving...';try{let r=await fetch('/api/patients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let result=await r.json();if(!r.ok)throw Error(result.detail||'Could not register patient');status.textContent='Registered '+result.patient_code;form.reset();await load();await selectPatient(result.id)}catch(err){status.textContent=err.message}}

async function drawNetwork(){const svg=document.getElementById('networkGraph');if(!svg)return;try{const data=await get('/api/network');const nodes=data.nodes.slice(0,45);const map=new Map(nodes.map((n,i)=>{const a=2*Math.PI*i/nodes.length-Math.PI/2;return[n.id,{...n,x:450+195*Math.cos(a),y:250+195*Math.sin(a)}]}));const edges=data.edges.filter(e=>map.has(e.source)&&map.has(e.target));const lines=edges.map(e=>{const a=map.get(e.source),b=map.get(e.target);return '<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="#607aa4" stroke-opacity=".45" stroke-width="'+(1+(e.weight-85)/8)+'"><title>Similarity '+e.weight+'%</title></line>'}).join('');const circles=nodes.map(n=>{const p=map.get(n.id),c=colors[n.diagnosis]||'#8ea9ff';return '<g onclick="selectPatient('+n.id+')" style="cursor:pointer"><circle cx="'+p.x+'" cy="'+p.y+'" r="10" fill="'+c+'" stroke="#eef4ff" stroke-width="1.5"><title>'+esc(n.label)+' · '+esc(n.diagnosis)+'</title></circle><text x="'+p.x+'" y="'+(p.y+24)+'" text-anchor="middle" fill="#dce6f7" font-size="10">'+esc(n.label)+'</text></g>'}).join('');svg.innerHTML='<rect width="900" height="500" fill="#0d1525" rx="10"/>'+lines+circles}catch(e){svg.innerHTML='<text x="20" y="35" fill="#f3c47a">Network could not load: '+esc(e.message)+'</text>'}}
async function selectPatient(id){let p=patients.find(x=>x.id===id);if(!p)return;tab('patients');document.getElementById('profile').innerHTML='<h3>'+esc(p.patient_code)+' · '+p.age+' years</h3><p>'+esc(p.sex)+' · '+esc(p.diagnosis)+'</p>'+domains.map(d=>'<div class="metric"><span>'+d.replace('_',' ')+'</span><b>'+p[d]+'</b></div><div class="bar"><span style="width:'+p[d]+'%"></span></div>').join('');try{let sim=await get('/api/patients/'+id+'/similar');document.getElementById('similar').innerHTML=sim.map(x=>'<div class="metric"><span>'+esc(x.patient_code)+' · '+esc(x.diagnosis)+'</span><b>'+x.similarity+'%</b></div>').join('')||'No other patients yet'}catch(e){document.getElementById('similar').textContent=e.message}}
async function importFile(input){let f=input.files[0];if(!f)return;let d=new FormData();d.append('file',f);try{let r=await fetch('/api/import-csv',{method:'POST',body:d});if(!r.ok)throw Error(await r.text());let x=await r.json();await load();alert('Imported '+x.added+' records')}catch(e){alert('CSV import failed: '+e.message)}input.value=''}
load();
drawNetwork();
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home(): return HTML
@app.get("/{full_path:path}", response_class=HTMLResponse)
def frontend_fallback(full_path: str):
    if full_path.startswith("api/"): raise HTTPException(404,"API route not found")
    return HTML
