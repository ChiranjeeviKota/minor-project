# Patient Similarity Network: single-file FastAPI backend + embedded frontend.
# Academic demo only. All initial records are synthetic; not for clinical decisions.
# Local run: pip install -r requirements.txt && uvicorn index:app --reload
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
import sqlite3, os, csv, io, random
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

def similarity(a,b):
    weights=[.22,.14,.18,.12,.12,.10,.12]
    weighted=sum(w*abs(float(a[d])-float(b[d])) for w,d in zip(weights,DOMAINS))
    return round(max(0,min(100,.7*(100-weighted)+.3*(100-sum(abs(float(a[d])-float(b[d])) for d in DOMAINS)/7))),1)

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
def similar_patients(pid:int):
    ps=all_patients()
    target=next((p for p in ps if p["id"]==pid),None)
    if not target: raise HTTPException(404,"Patient not found")
    return sorted([{**p,"similarity":similarity(target,p)} for p in ps if p["id"]!=pid],key=lambda p:p["similarity"],reverse=True)[:10]
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
def clusters():
    result=[]
    for p in all_patients():
        avg=sum(p[d] for d in DOMAINS)/len(DOMAINS)
        result.append({"patient_id":p["id"],"cluster":0 if avg>=70 else 1 if avg>=48 else 2})
    return {"clusters":result,"note":"Rule-based demonstration only; not clinically validated."}
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
</style></head><body><main><header><div><h1>Patient Similarity Network</h1><div class="muted">Cognitive networks · Alzheimer’s research prototype</div></div><b style="color:var(--mint)">● API-POWERED DEMO</b></header><div class="notice">Academic research demo only. Records shown by default are synthetic. Not clinically validated; do not use for diagnosis or treatment decisions.</div><nav class="nav"><button class="active" data-tab="overview">Overview</button><button data-tab="network">Patient Network</button><button data-tab="patients">Patient Explorer</button><button data-tab="research">Research Lab</button></nav><div id="error" class="notice hidden"></div><div id="overview"><div class="cards" id="stats"></div><div class="two"><section><h2>Cohort distribution</h2><div id="distribution"></div></section><section><h2>Quick actions</h2><p class="muted">Explore profiles, compare cognitive-domain similarity, inspect network relationships and export records.</p><button class="primary" onclick="tab('patients')">Explore patients</button> <button onclick="load()">Refresh</button> <button onclick="location.href='/api/export-csv'">Export CSV</button><p id="mean" class="muted"></p></section></div></div><div id="network" class="hidden"><section><h2>Patient similarity network</h2><p class="muted">Select a synthetic patient to compare cognitive domains.</p><div id="networkgrid" class="patientgrid"></div></section></div><div id="patients" class="hidden"><section><h2>Patient explorer</h2><div class="toolbar"><input id="q" placeholder="Search patient code" oninput="renderPatients()"><select id="filter" onchange="renderPatients()"><option>All</option><option>Healthy</option><option>MCI</option><option>Alzheimer's</option></select><button onclick="location.href='/api/export-csv'">Export CSV</button><label class="btn">Import CSV<input type="file" accept=".csv" hidden onchange="importFile(this)"></label></div><div class="tablewrap"><table><thead><tr><th>Patient</th><th>Age</th><th>Diagnosis</th><th>MMSE</th><th>MoCA</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></section><div class="two"><section><h2>Selected profile</h2><div id="profile" class="muted">Choose Compare on a patient.</div></section><section><h2>Closest similar patients</h2><div id="similar" class="muted">Choose a patient to compare.</div></section></div></div><div id="research" class="hidden"><div class="cards" id="researchcards"></div><section><h2>Research evaluation</h2><p class="muted">Exploratory similarity and rule-based grouping on synthetic data; not clinical evidence.</p><div id="researchtext"></div><button onclick="load()">Recalculate</button></section></div></main><script>
let patients=[],stats={};const domains=['memory','attention','executive','language','visuospatial','processing_speed','orientation'];const colors={Healthy:'var(--mint)',MCI:'var(--blue)',"Alzheimer's":'var(--gold)'};
function tab(n){document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===n));['overview','network','patients','research'].forEach(x=>document.getElementById(x).classList.toggle('hidden',x!==n))}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>tab(b.dataset.tab));
async function get(u){let r=await fetch(u);if(!r.ok)throw Error((await r.text()).slice(0,150));return r.json()}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){try{document.getElementById('error').classList.add('hidden');[patients,stats]=await Promise.all([get('/api/patients'),get('/api/stats')]);render()}catch(e){let x=document.getElementById('error');x.textContent='Could not load data: '+e.message;x.classList.remove('hidden')}}
function render(){document.getElementById('stats').innerHTML=[['Total patients',stats.total],['Healthy cohort',stats.healthy],['MCI cohort',stats.mci],["Alzheimer’s cohort",stats.alzheimers]].map(([a,b])=>'<div class="card"><small>'+a+'</small><strong>'+(b??'—')+'</strong><small>Synthetic sample records</small></div>').join('');let total=stats.total||1;document.getElementById('distribution').innerHTML=[['Healthy',stats.healthy],['MCI',stats.mci],["Alzheimer's",stats.alzheimers]].map(([n,v])=>'<div class="metric"><span>'+n+'</span><b>'+v+'</b></div><div class="bar"><span style="width:'+(v/total*100)+'%;background:'+colors[n]+'"></span></div>').join('');document.getElementById('mean').textContent='Mean MMSE: '+stats.mean_mmse+' / 30';document.getElementById('networkgrid').innerHTML=patients.slice(0,30).map(p=>'<button class="patient" onclick="selectPatient('+p.id+')"><b>'+esc(p.patient_code)+'</b><span style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</span><small>Age '+p.age+' · MMSE '+p.mmse+'</small></button>').join('');renderPatients();document.getElementById('researchcards').innerHTML=[['Records',stats.total],['Cohorts',3],['Similarity','Weighted'],['Clinical status','Not validated']].map(([a,b])=>'<div class="card"><small>'+a+'</small><strong style="font-size:21px">'+b+'</strong></div>').join('');document.getElementById('researchtext').textContent='Similarity compares seven cognitive domains. Grouping is a transparent demonstration, not a validated clinical algorithm.'}
function renderPatients(){let q=(document.getElementById('q')?.value||'').toLowerCase(),f=document.getElementById('filter')?.value||'All';let list=patients.filter(p=>p.patient_code.toLowerCase().includes(q)&&(f==='All'||p.diagnosis===f));document.getElementById('rows').innerHTML=list.map(p=>'<tr><td>'+esc(p.patient_code)+'</td><td>'+p.age+'</td><td style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</td><td>'+p.mmse+'</td><td>'+p.moca+'</td><td><button onclick="selectPatient('+p.id+')">Compare</button></td></tr>').join('')}
async function selectPatient(id){let p=patients.find(x=>x.id===id);if(!p)return;tab('patients');document.getElementById('profile').innerHTML='<h3>'+esc(p.patient_code)+' · '+p.age+' years</h3><p>'+esc(p.sex)+' · '+esc(p.diagnosis)+'</p>'+domains.map(d=>'<div class="metric"><span>'+d.replace('_',' ')+'</span><b>'+p[d]+'</b></div><div class="bar"><span style="width:'+p[d]+'%"></span></div>').join('');try{let sim=await get('/api/patients/'+id+'/similar');document.getElementById('similar').innerHTML=sim.map(x=>'<div class="metric"><span>'+esc(x.patient_code)+' · '+esc(x.diagnosis)+'</span><b>'+x.similarity+'%</b></div>').join('')||'No other patients yet'}catch(e){document.getElementById('similar').textContent=e.message}}
async function importFile(input){let f=input.files[0];if(!f)return;let d=new FormData();d.append('file',f);try{let r=await fetch('/api/import-csv',{method:'POST',body:d});if(!r.ok)throw Error(await r.text());let x=await r.json();await load();alert('Imported '+x.added+' records')}catch(e){alert('CSV import failed: '+e.message)}input.value=''}
load();
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home(): return HTML
@app.get("/{full_path:path}", response_class=HTMLResponse)
def frontend_fallback(full_path: str):
    if full_path.startswith("api/"): raise HTTPException(404,"API route not found")
    return HTML
