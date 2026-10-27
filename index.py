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

# Account access: PBKDF2 password hashes and signed, HTTP-only sessions.
import hashlib, hmac, secrets, time, base64, json
from fastapi import Request
from fastapi.responses import JSONResponse

def auth_tables():
    db=connect()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL)""")
    db.commit()
    # Optional first-admin bootstrap. Set both values as Vercel environment variables.
    admin_email=os.getenv("PSN_ADMIN_EMAIL","").strip().lower()
    admin_password=os.getenv("PSN_ADMIN_PASSWORD","")
    if admin_email and admin_password and len(admin_password)>=12:
        row=db.execute("SELECT id FROM users WHERE email=?",(admin_email,)).fetchone()
        if not row:
            db.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
              ("PSN Administrator",admin_email,hash_password(admin_password),"admin",date.today().isoformat()))
            db.commit()
    db.close()

def hash_password(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
    return base64.urlsafe_b64encode(salt).decode()+"$"+base64.urlsafe_b64encode(digest).decode()

def verify_password(password, encoded):
    try:
        salt_b64,digest_b64=encoded.split("$",1)
        salt=base64.urlsafe_b64decode(salt_b64.encode())
        expected=base64.urlsafe_b64decode(digest_b64.encode())
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
        return hmac.compare_digest(actual,expected)
    except Exception: return False

def session_secret():
    secret=os.getenv("PSN_SESSION_SECRET","")
    if len(secret)<32: return None
    return secret.encode()

def make_session(user_id):
    secret=session_secret()
    if not secret: raise HTTPException(503,"Authentication is not configured. Set PSN_SESSION_SECRET to a random value of at least 32 characters.")
    payload=f"{user_id}.{int(time.time())+60*60*12}"
    sig=hmac.new(secret,payload.encode(),hashlib.sha256).hexdigest()
    return payload+"."+sig

def current_user_from_cookie(cookie):
    secret=session_secret()
    if not secret or not cookie: return None
    try:
        user_id,expires,sig=cookie.split(".",2)
        payload=user_id+"."+expires
        expected=hmac.new(secret,payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected) or int(expires)<int(time.time()): return None
        db=connect()
        row=db.execute("SELECT id,name,email,role,created_at FROM users WHERE id=?",(int(user_id),)).fetchone()
        db.close()
        return dict(row) if row else None
    except Exception: return None

@app.middleware("http")
async def require_account(request: Request, call_next):
    # Demo mode: account gating is disabled; portal-enabled code is saved on CHIRU-portals-saved.
    return await call_next(request)

class RegisterIn(BaseModel):
    name: str = Field(min_length=2,max_length=80)
    email: str = Field(min_length=5,max_length=254)
    password: str = Field(min_length=10,max_length=128)

class LoginIn(BaseModel):
    email: str = Field(min_length=5,max_length=254)
    password: str = Field(min_length=1,max_length=128)

@app.post("/api/auth/register")
def register_account(data:RegisterIn):
    email=data.email.strip().lower()
    if "@" not in email or "." not in email.rsplit("@",1)[-1]:
        raise HTTPException(400,"Enter a valid email address.")
    if len(data.password)<10:
        raise HTTPException(400,"Use a password with at least 10 characters.")
    db=connect()
    try:
        cur=db.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
          (data.name.strip(),email,hash_password(data.password),"analyst",date.today().isoformat()))
        db.commit()
        user_id=cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409,"An account with this email already exists.")
    finally: db.close()
    token=make_session(user_id)
    response=JSONResponse({"ok":True,"user":current_user_from_cookie(token)})
    response.set_cookie("psn_session",token,httponly=True,secure=bool(os.getenv("VERCEL")),samesite="strict",max_age=43200,path="/")
    return response

@app.post("/api/auth/login")
def login_account(data:LoginIn):
    email=data.email.strip().lower()
    db=connect()
    row=db.execute("SELECT id,password_hash FROM users WHERE email=?",(email,)).fetchone()
    db.close()
    if not row or not verify_password(data.password,row["password_hash"]):
        raise HTTPException(401,"Email or password is incorrect.")
    token=make_session(row["id"])
    response=JSONResponse({"ok":True,"user":current_user_from_cookie(token)})
    response.set_cookie("psn_session",token,httponly=True,secure=bool(os.getenv("VERCEL")),samesite="strict",max_age=43200,path="/")
    return response

@app.get("/api/auth/me")
def auth_me(request:Request):
    user=current_user_from_cookie(request.cookies.get("psn_session"))
    return {"user":user}

@app.post("/api/auth/logout")
def logout_account():
    response=JSONResponse({"ok":True})
    response.delete_cookie("psn_session",path="/")
    return response

def require_admin_request(request: Request):
    user=current_user_from_cookie(request.cookies.get("psn_session"))
    if not user:
        raise HTTPException(401,"Sign in required.")
    if user.get("role")!="admin":
        raise HTTPException(403,"Administrator access required.")
    return user

@app.get("/api/admin/users")
def admin_users(request: Request):
    require_admin_request(request)
    db=connect()
    rows=db.execute("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

class RoleIn(BaseModel):
    role: str

@app.patch("/api/admin/users/{user_id}/role")
def change_user_role(user_id:int,data:RoleIn,request:Request):
    require_admin_request(request)
    if data.role not in ("admin","analyst"): raise HTTPException(400,"Role must be admin or analyst.")
    db=connect()
    exists=db.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone()
    if not exists: db.close(); raise HTTPException(404,"Account not found.")
    if data.role=="analyst":
        admins=db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        current=db.execute("SELECT role FROM users WHERE id=?",(user_id,)).fetchone()["role"]
        if current=="admin" and admins<=1: db.close(); raise HTTPException(400,"Keep at least one admin account.")
    db.execute("UPDATE users SET role=? WHERE id=?",(data.role,user_id)); db.commit(); db.close()
    return {"ok":True}

auth_tables()


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
def network(threshold: float = 85, diagnosis: str | None = None):
    if not 0 <= threshold <= 100: raise HTTPException(400, "Threshold must be between 0 and 100")
    ps=all_patients()
    if diagnosis and diagnosis != "All": ps=[p for p in ps if p["diagnosis"] == diagnosis]
    nodes=[{"id":p["id"],"label":p["patient_code"],"diagnosis":p["diagnosis"],"age":p["age"]} for p in ps]; edges=[]
    for i,p in enumerate(ps):
        for other in ps[i+1:]:
            score=similarity(p,other)
            if score>=threshold: edges.append({"source":p["id"],"target":other["id"],"weight":score})
    return {"nodes":nodes,"edges":edges,"threshold":threshold,"diagnosis":diagnosis or "All"}

@app.get("/api/patients/{pid}/explanation")
def explain_similarity(pid: int, compare_to: int | None = None, method: str = "weighted"):
    if method not in ("weighted", "cosine", "euclidean"): raise HTTPException(400, "Unknown similarity method")
    ps=all_patients(); target=next((p for p in ps if p["id"]==pid),None)
    if not target: raise HTTPException(404,"Patient not found")
    candidates=[p for p in ps if p["id"]!=pid]
    if compare_to is not None: candidates=[p for p in candidates if p["id"]==compare_to]
    if not candidates: raise HTTPException(404,"Comparison patient not found")
    other=max(candidates,key=lambda p:similarity(target,p,method))
    weights={"memory":.22,"attention":.14,"executive":.18,"language":.12,"visuospatial":.12,"processing_speed":.10,"orientation":.12}
    rows=[]
    for domain in DOMAINS:
        gap=abs(float(target[domain])-float(other[domain]))
        rows.append({"domain":domain,"patient_value":target[domain],"comparison_value":other[domain],"absolute_gap":round(gap,1),"weight_percent":round(weights[domain]*100,1),"distance_contribution":round(weights[domain]*gap,2)})
    rows.sort(key=lambda x:x["distance_contribution"],reverse=True)
    return {"patient_code":target["patient_code"],"comparison_code":other["patient_code"],"similarity":similarity(target,other,method),"method":method,"domains":rows,"explanation":"Domain contributions describe the configured weighted-distance formula, not causal or trained-model feature importance.","note":"Exploratory comparison on synthetic demo records; not a diagnosis."}
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
        db.execute("UPDATE patients SET visit=visit+1,visit_date=?,mmse=?,moca=?,memory=?,attention=?,executive=?,language=?,visuospatial=?,processing_speed=?,orientation=? WHERE id=?",
          (v.visit_date,v.mmse,v.moca,v.memory,v.attention,v.executive,v.language,v.visuospatial,v.processing_speed,v.orientation,pid))
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
@app.get("/api/report", response_class=HTMLResponse)
def printable_report():
    st=stats(); ev=evaluation(); gf=graph_features(85); ps=all_patients()
    rows="".join("<tr><td>"+str(p["patient_code"])+"</td><td>"+str(p["diagnosis"])+"</td><td>"+str(p["mmse"])+"</td><td>"+str(p["moca"])+"</td></tr>" for p in ps)
    html=("""<!doctype html><html><head><meta charset="utf-8"><title>PSN Research Summary</title><style>
:root{color-scheme:dark;--bg:#080d19;--surface:#10192a;--surface2:#151f33;--line:#263650;--muted:#a3b1c8;--text:#f1f5ff;--mint:#8ce6c6;--blue:#9db6ff;--gold:#f4cc83;--violet:#c4b5fd;--radius:20px}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:100px}body{margin:0;background:radial-gradient(ellipse at 50% -10%,#1a3150 0,transparent 42%),var(--bg);font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:var(--text)}main{max-width:1320px;margin:auto;padding:24px 30px 110px}
header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:8px 0 22px;border-bottom:1px solid #202d43}
.brand{display:flex;align-items:center;gap:13px}.brand-mark{width:46px;height:46px;display:grid;place-items:center;border-radius:15px;background:linear-gradient(145deg,#9bf1d4,#8ea9ff);color:#0b1724;font-size:22px;font-weight:900;box-shadow:0 8px 28px #8ea9ff22}.brand h1{font-size:19px;letter-spacing:-.4px;margin:0}.brand p{font-size:12px;color:var(--muted);margin:1px 0 0}
h1,h2,h3,p{overflow-wrap:anywhere}h2{font-size:19px;letter-spacing:-.35px;margin:0 0 8px}h3{font-size:15px}.muted,small{color:var(--muted)}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.notice{padding:12px 16px;border:1px solid #744d3b;background:#2b211f;color:#f1c9b8;border-radius:12px;margin:16px 0}.nav{display:flex;gap:7px;flex-wrap:wrap;margin:18px 0 24px;padding:7px;border:1px solid #263650;background:#0d1524;border-radius:16px;position:sticky;top:8px;z-index:20;backdrop-filter:blur(16px);box-shadow:0 12px 36px #0002}
button,.btn,select,input,textarea{font:inherit;border:1px solid #30415c;background:#121e32;color:var(--text);border-radius:11px;padding:10px 13px;transition:border-color .18s,background .18s,transform .18s}button,.btn{cursor:pointer;font-weight:650}button:hover,.btn:hover{border-color:#8ce6c6;transform:translateY(-1px)}button.active,.primary{background:var(--mint);border-color:var(--mint);color:#092219;font-weight:800}.nav button{border-color:transparent;background:transparent;color:#aebbd0;padding:10px 13px;font-size:13px}.nav button.active{background:#d5fff0;color:#0b3026;box-shadow:0 3px 12px #8ce6c622}.btn{display:inline-flex;align-items:center}input,select,textarea{cursor:text;max-width:100%}select{cursor:pointer}input:focus,select:focus,textarea:focus,button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.hero{position:relative;overflow:hidden;display:grid;grid-template-columns:minmax(0,1.35fr) minmax(250px,.65fr);gap:30px;align-items:center;padding:clamp(24px,4vw,48px);border:1px solid #344866;border-radius:28px;background:linear-gradient(120deg,#172b46 0%,#151e35 55%,#211d3c 100%);box-shadow:0 24px 80px #0002;margin-bottom:20px}.hero:after{content:"";position:absolute;width:340px;height:340px;border-radius:50%;right:-90px;top:-140px;background:radial-gradient(circle,#8ce6c622,transparent 68%);pointer-events:none}.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--mint);font-weight:850}.hero h2{font-size:clamp(30px,4.5vw,52px);line-height:1.08;letter-spacing:-1.8px;margin:14px 0}.hero p{max-width:640px;color:#c1cee2;font-size:16px;margin:0 0 22px}.hero-actions{display:flex;gap:10px;flex-wrap:wrap}.hero-art{min-height:200px;display:grid;place-items:center;position:relative;z-index:1}.network-art{width:min(100%,330px);height:auto;filter:drop-shadow(0 18px 36px #0003)}.hero-kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:24px}.hero-kpi{border-top:1px solid #ffffff20;padding-top:12px}.hero-kpi strong{font-size:23px;display:block}.hero-kpi span{font-size:11px;color:#aebbd0}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0 24px}.card,section{background:linear-gradient(155deg,#121d30,#0e1727);border:1px solid #263650;border-radius:var(--radius);padding:21px;margin-bottom:16px;box-shadow:0 8px 24px #0000000b}.card{margin:0;min-width:0}.card strong{display:block;font-size:32px;letter-spacing:-.8px;margin:8px 0 2px}.card small{font-size:12px}.card-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:#24334b;color:var(--mint);font-size:18px;margin-bottom:14px}.section-heading{display:flex;justify-content:space-between;align-items:end;gap:16px;margin:28px 0 12px}.section-heading h2{margin:0}.feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.feature-card{padding:20px;border:1px solid #263650;background:#111b2d;border-radius:18px}.feature-card p{font-size:13px;color:var(--muted);margin:8px 0 14px}.feature-card .feature-icon{font-size:22px;margin-bottom:10px}.feature-card button{font-size:12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}.two>section{min-width:0}.toolbar{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:14px 0}.toolbar label{display:flex;gap:8px;align-items:center;flex-wrap:wrap;color:#b5c2d6;font-size:13px}.tablewrap{overflow:auto;border:1px solid #263650;border-radius:13px}table{width:100%;border-collapse:collapse;min-width:560px;background:#0d1626}td,th{text-align:left;padding:12px 14px;border-bottom:1px solid #223149}th{color:#aab9d0;font-size:11px;text-transform:uppercase;letter-spacing:.7px;background:#121e31}tr:last-child td{border-bottom:0}.hidden{display:none!important}.metric{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #263650}.bar{height:7px;background:#263650;margin:6px 0 12px;border-radius:9px;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--mint),var(--blue));border-radius:9px}.patientgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.patient{display:flex;flex-direction:column;align-items:flex-start;width:100%}.admin-hero{display:flex;align-items:center;justify-content:space-between;gap:20px;background:linear-gradient(120deg,#172b47,#1a1d38 70%,#292149);border-color:#354665;padding:24px}.admin-hero h2{font-size:26px;margin:8px 0}.admin-hero-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.secure-chip,.count-pill,.role-pill{display:inline-flex;align-items:center;gap:6px;border:1px solid #30415c;border-radius:999px;padding:6px 10px;font-size:11px;white-space:nowrap}.secure-chip{color:var(--mint);border-color:#2d675b;background:#14322f}.admin-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0 0 14px}.admin-stat{background:#151f34;border:1px solid #263650;border-radius:14px;padding:18px}.admin-stat span,.admin-stat small{display:block;color:var(--muted)}.admin-stat strong{display:block;font-size:30px;margin:6px 0}.admin-directory{padding:0;overflow:hidden}.directory-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:20px 20px 10px}.directory-head h2{margin:0 0 4px}.directory-head p{margin:0}.count-pill{color:var(--blue)}.admin-tools{padding:0 20px;margin:8px 0 16px}.admin-tools input{width:min(420px,100%)}.admin-users{padding:0 20px 20px}.admin-users table{min-width:680px}.admin-users td{padding:13px 10px}.account-cell{display:flex;align-items:center;gap:10px}.account-cell small{display:block;margin-top:2px}.avatar{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#253451;color:#d9e3ff;font-weight:800}.role-pill{font-size:10px;font-weight:700}.role-admin{color:#e2d7ff;background:#2b2348;border-color:#514178}.role-analyst{color:#a6e8d4;background:#15352f;border-color:#2d6255}.admin-footnote,.footer-note{color:var(--muted);font-size:12px}.empty-state{padding:24px;color:var(--muted)}
.site-footer{margin-top:38px;padding:26px 0 6px;border-top:1px solid #263650;display:flex;justify-content:space-between;gap:18px;align-items:center;color:var(--muted);font-size:12px}.footer-brand{font-weight:800;color:#eaf1ff}.bottom-nav{display:none}
#adminButton,#adminNav,#admin{display:none!important}#signedInAs,button[onclick="logout()"]{display:none!important}
@media(max-width:950px){main{padding:18px 18px 100px}.hero{grid-template-columns:1fr .55fr;gap:12px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.feature-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.nav{position:relative;top:auto}.nav button{font-size:12px;padding:9px}}
@media(max-width:650px){main{padding:12px 12px 100px}.brand-mark{width:40px;height:40px}.brand h1{font-size:17px}.hero{grid-template-columns:1fr;padding:25px 21px;border-radius:22px}.hero h2{font-size:35px}.hero p{font-size:14px}.hero-art{display:none}.hero-kpis{gap:7px}.hero-kpi strong{font-size:20px}.hero-kpi span{font-size:10px}.cards{gap:9px}.card{padding:15px;border-radius:16px}.card strong{font-size:27px}.two,.feature-grid{grid-template-columns:1fr}.patientgrid{grid-template-columns:repeat(2,minmax(0,1fr))}.nav{display:none}.bottom-nav{position:fixed;z-index:50;bottom:10px;left:10px;right:10px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:3px;padding:7px;background:#101a2bed;border:1px solid #34435d;border-radius:18px;box-shadow:0 14px 40px #0008;backdrop-filter:blur(20px)}.bottom-nav button{background:transparent;border:0;color:#aebbd0;padding:8px 2px;font-size:10px;display:flex;flex-direction:column;align-items:center;gap:3px;min-width:0}.bottom-nav button span{font-size:18px;line-height:1.2}.bottom-nav button.active{background:#d5fff0;color:#0b3026;border-radius:12px}.site-footer{flex-direction:column;align-items:flex-start}.section-heading{align-items:flex-start;flex-direction:column}.toolbar input{min-width:0}.admin-stats{grid-template-columns:1fr}.admin-hero{align-items:flex-start;flex-direction:column}.directory-head{align-items:flex-start;flex-direction:column}}
@media(max-width:380px){.patientgrid{grid-template-columns:1fr}.hero h2{font-size:30px}.hero-kpi strong{font-size:18px}}


/* FINAL FIX: ensure the animated brain is mounted visibly in the Home hero */
#psn-neural-bg{z-index:0!important}
#appShell, #authScreen{position:relative;z-index:1}
#overview>.hero{position:relative}
#overview>.hero>.brain-visual{
 display:flex!important;visibility:visible!important;opacity:1!important;
 grid-column:2;grid-row:1;min-width:0;min-height:340px;width:100%;
 align-self:stretch;position:relative;z-index:2;overflow:hidden;
}
#overview>.hero>.brain-visual .brain-svg{display:block!important;visibility:visible!important;opacity:1!important;width:116%;max-width:700px;height:auto}
@media(max-width:1050px){#overview>.hero>.brain-visual{grid-column:2;grid-row:1;min-height:280px}}
@media(max-width:700px){#overview>.hero>.brain-visual{grid-column:1;grid-row:2;min-height:270px}}
</style></head><body><button onclick="window.print()">Print / Save as PDF</button><h1>Patient Similarity Network — Research Summary</h1><p>Generated """+date.today().isoformat()+""" · Synthetic demo records</p><div class="grid"><div class="card">Total records<br><b>"""+str(st["total"])+"""</b></div><div class="card">Healthy cohort<br><b>"""+str(st["healthy"])+"""</b></div><div class="card">MCI cohort<br><b>"""+str(st["mci"])+"""</b></div><div class="card">Alzheimer’s cohort<br><b>"""+str(st["alzheimers"])+"""</b></div><div class="card">Mean MMSE<br><b>"""+str(st["mean_mmse"])+"""/30</b></div><div class="card">Network edges ≥85%<br><b>"""+str(gf["edges"])+"""</b></div></div><h2>Exploratory clustering evaluation</h2><p>Silhouette score: """+str(ev.get("silhouette"))+""" · Records: """+str(ev.get("patients"))+"""</p><p>"""+str(ev.get("note",""))+"""</p><h2>Patient summary</h2><table><thead><tr><th>Patient code</th><th>Cohort label</th><th>MMSE</th><th>MoCA</th></tr></thead><tbody>"""+rows+"""</tbody></table><p class="note"><b>Important:</b> Academic research prototype. Records are synthetic by default; metrics are exploratory and not clinically validated. Not a diagnosis and must not guide treatment decisions.</p>
<script>
/* FINAL FIX: mount a guaranteed visible brain graphic in Home after all layout scripts. */
(function(){
 function mountPSNBrain(){
  const overview=document.getElementById('overview');
  const hero=overview&&overview.querySelector('.hero');
  if(!hero)return;
  let visual=hero.querySelector('.brain-visual');
  if(!visual){
   const source=document.querySelector('#analytics .brain-visual');
   if(source){visual=source.cloneNode(true);hero.appendChild(visual);}
  }
  if(visual){
   visual.style.setProperty('display','flex','important');
   visual.style.setProperty('visibility','visible','important');
   visual.style.setProperty('opacity','1','important');
   visual.style.setProperty('min-height',window.innerWidth<700?'270px':'340px','important');
   visual.style.setProperty('grid-column',window.innerWidth<700?'1':'2');
   visual.style.setProperty('grid-row',window.innerWidth<700?'2':'1');
   const svg=visual.querySelector('.brain-svg');
   if(svg){svg.style.setProperty('display','block','important');svg.style.setProperty('visibility','visible','important');svg.style.setProperty('opacity','1','important');}
  }
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mountPSNBrain);
 else mountPSNBrain();
 window.addEventListener('load',mountPSNBrain,{once:true});
})();
</script>
</body></html>""")
    return HTMLResponse(html)

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
:root{color-scheme:dark;--bg:#080d19;--surface:#10192a;--surface2:#151f33;--line:#263650;--muted:#a3b1c8;--text:#f1f5ff;--mint:#8ce6c6;--blue:#9db6ff;--gold:#f4cc83;--violet:#c4b5fd;--radius:20px}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:100px}body{margin:0;background:radial-gradient(ellipse at 50% -10%,#1a3150 0,transparent 42%),var(--bg);font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:var(--text)}main{max-width:1320px;margin:auto;padding:24px 30px 110px}
header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:8px 0 22px;border-bottom:1px solid #202d43}
.brand{display:flex;align-items:center;gap:13px}.brand-mark{width:46px;height:46px;display:grid;place-items:center;border-radius:15px;background:linear-gradient(145deg,#9bf1d4,#8ea9ff);color:#0b1724;font-size:22px;font-weight:900;box-shadow:0 8px 28px #8ea9ff22}.brand h1{font-size:19px;letter-spacing:-.4px;margin:0}.brand p{font-size:12px;color:var(--muted);margin:1px 0 0}
h1,h2,h3,p{overflow-wrap:anywhere}h2{font-size:19px;letter-spacing:-.35px;margin:0 0 8px}h3{font-size:15px}.muted,small{color:var(--muted)}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.notice{padding:12px 16px;border:1px solid #744d3b;background:#2b211f;color:#f1c9b8;border-radius:12px;margin:16px 0}.nav{display:flex;gap:7px;flex-wrap:wrap;margin:18px 0 24px;padding:7px;border:1px solid #263650;background:#0d1524;border-radius:16px;position:sticky;top:8px;z-index:20;backdrop-filter:blur(16px);box-shadow:0 12px 36px #0002}
button,.btn,select,input,textarea{font:inherit;border:1px solid #30415c;background:#121e32;color:var(--text);border-radius:11px;padding:10px 13px;transition:border-color .18s,background .18s,transform .18s}button,.btn{cursor:pointer;font-weight:650}button:hover,.btn:hover{border-color:#8ce6c6;transform:translateY(-1px)}button.active,.primary{background:var(--mint);border-color:var(--mint);color:#092219;font-weight:800}.nav button{border-color:transparent;background:transparent;color:#aebbd0;padding:10px 13px;font-size:13px}.nav button.active{background:#d5fff0;color:#0b3026;box-shadow:0 3px 12px #8ce6c622}.btn{display:inline-flex;align-items:center}input,select,textarea{cursor:text;max-width:100%}select{cursor:pointer}input:focus,select:focus,textarea:focus,button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.hero{position:relative;overflow:hidden;display:grid;grid-template-columns:minmax(0,1.35fr) minmax(250px,.65fr);gap:30px;align-items:center;padding:clamp(24px,4vw,48px);border:1px solid #344866;border-radius:28px;background:linear-gradient(120deg,#172b46 0%,#151e35 55%,#211d3c 100%);box-shadow:0 24px 80px #0002;margin-bottom:20px}.hero:after{content:"";position:absolute;width:340px;height:340px;border-radius:50%;right:-90px;top:-140px;background:radial-gradient(circle,#8ce6c622,transparent 68%);pointer-events:none}.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--mint);font-weight:850}.hero h2{font-size:clamp(30px,4.5vw,52px);line-height:1.08;letter-spacing:-1.8px;margin:14px 0}.hero p{max-width:640px;color:#c1cee2;font-size:16px;margin:0 0 22px}.hero-actions{display:flex;gap:10px;flex-wrap:wrap}.hero-art{min-height:200px;display:grid;place-items:center;position:relative;z-index:1}.network-art{width:min(100%,330px);height:auto;filter:drop-shadow(0 18px 36px #0003)}.hero-kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:24px}.hero-kpi{border-top:1px solid #ffffff20;padding-top:12px}.hero-kpi strong{font-size:23px;display:block}.hero-kpi span{font-size:11px;color:#aebbd0}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0 24px}.card,section{background:linear-gradient(155deg,#121d30,#0e1727);border:1px solid #263650;border-radius:var(--radius);padding:21px;margin-bottom:16px;box-shadow:0 8px 24px #0000000b}.card{margin:0;min-width:0}.card strong{display:block;font-size:32px;letter-spacing:-.8px;margin:8px 0 2px}.card small{font-size:12px}.card-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:#24334b;color:var(--mint);font-size:18px;margin-bottom:14px}.section-heading{display:flex;justify-content:space-between;align-items:end;gap:16px;margin:28px 0 12px}.section-heading h2{margin:0}.feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.feature-card{padding:20px;border:1px solid #263650;background:#111b2d;border-radius:18px}.feature-card p{font-size:13px;color:var(--muted);margin:8px 0 14px}.feature-card .feature-icon{font-size:22px;margin-bottom:10px}.feature-card button{font-size:12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}.two>section{min-width:0}.toolbar{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:14px 0}.toolbar label{display:flex;gap:8px;align-items:center;flex-wrap:wrap;color:#b5c2d6;font-size:13px}.tablewrap{overflow:auto;border:1px solid #263650;border-radius:13px}table{width:100%;border-collapse:collapse;min-width:560px;background:#0d1626}td,th{text-align:left;padding:12px 14px;border-bottom:1px solid #223149}th{color:#aab9d0;font-size:11px;text-transform:uppercase;letter-spacing:.7px;background:#121e31}tr:last-child td{border-bottom:0}.hidden{display:none!important}.metric{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #263650}.bar{height:7px;background:#263650;margin:6px 0 12px;border-radius:9px;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--mint),var(--blue));border-radius:9px}.patientgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.patient{display:flex;flex-direction:column;align-items:flex-start;width:100%}.admin-hero{display:flex;align-items:center;justify-content:space-between;gap:20px;background:linear-gradient(120deg,#172b47,#1a1d38 70%,#292149);border-color:#354665;padding:24px}.admin-hero h2{font-size:26px;margin:8px 0}.admin-hero-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.secure-chip,.count-pill,.role-pill{display:inline-flex;align-items:center;gap:6px;border:1px solid #30415c;border-radius:999px;padding:6px 10px;font-size:11px;white-space:nowrap}.secure-chip{color:var(--mint);border-color:#2d675b;background:#14322f}.admin-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0 0 14px}.admin-stat{background:#151f34;border:1px solid #263650;border-radius:14px;padding:18px}.admin-stat span,.admin-stat small{display:block;color:var(--muted)}.admin-stat strong{display:block;font-size:30px;margin:6px 0}.admin-directory{padding:0;overflow:hidden}.directory-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:20px 20px 10px}.directory-head h2{margin:0 0 4px}.directory-head p{margin:0}.count-pill{color:var(--blue)}.admin-tools{padding:0 20px;margin:8px 0 16px}.admin-tools input{width:min(420px,100%)}.admin-users{padding:0 20px 20px}.admin-users table{min-width:680px}.admin-users td{padding:13px 10px}.account-cell{display:flex;align-items:center;gap:10px}.account-cell small{display:block;margin-top:2px}.avatar{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#253451;color:#d9e3ff;font-weight:800}.role-pill{font-size:10px;font-weight:700}.role-admin{color:#e2d7ff;background:#2b2348;border-color:#514178}.role-analyst{color:#a6e8d4;background:#15352f;border-color:#2d6255}.admin-footnote,.footer-note{color:var(--muted);font-size:12px}.empty-state{padding:24px;color:var(--muted)}
.site-footer{margin-top:38px;padding:26px 0 6px;border-top:1px solid #263650;display:flex;justify-content:space-between;gap:18px;align-items:center;color:var(--muted);font-size:12px}.footer-brand{font-weight:800;color:#eaf1ff}.bottom-nav{display:none}
#adminButton,#adminNav,#admin{display:none!important}#signedInAs,button[onclick="logout()"]{display:none!important}
@media(max-width:950px){main{padding:18px 18px 100px}.hero{grid-template-columns:1fr .55fr;gap:12px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.feature-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.nav{position:relative;top:auto}.nav button{font-size:12px;padding:9px}}
@media(max-width:650px){main{padding:12px 12px 100px}.brand-mark{width:40px;height:40px}.brand h1{font-size:17px}.hero{grid-template-columns:1fr;padding:25px 21px;border-radius:22px}.hero h2{font-size:35px}.hero p{font-size:14px}.hero-art{display:none}.hero-kpis{gap:7px}.hero-kpi strong{font-size:20px}.hero-kpi span{font-size:10px}.cards{gap:9px}.card{padding:15px;border-radius:16px}.card strong{font-size:27px}.two,.feature-grid{grid-template-columns:1fr}.patientgrid{grid-template-columns:repeat(2,minmax(0,1fr))}.nav{display:none}.bottom-nav{position:fixed;z-index:50;bottom:10px;left:10px;right:10px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:3px;padding:7px;background:#101a2bed;border:1px solid #34435d;border-radius:18px;box-shadow:0 14px 40px #0008;backdrop-filter:blur(20px)}.bottom-nav button{background:transparent;border:0;color:#aebbd0;padding:8px 2px;font-size:10px;display:flex;flex-direction:column;align-items:center;gap:3px;min-width:0}.bottom-nav button span{font-size:18px;line-height:1.2}.bottom-nav button.active{background:#d5fff0;color:#0b3026;border-radius:12px}.site-footer{flex-direction:column;align-items:flex-start}.section-heading{align-items:flex-start;flex-direction:column}.toolbar input{min-width:0}.admin-stats{grid-template-columns:1fr}.admin-hero{align-items:flex-start;flex-direction:column}.directory-head{align-items:flex-start;flex-direction:column}}
@media(max-width:380px){.patientgrid{grid-template-columns:1fr}.hero h2{font-size:30px}.hero-kpi strong{font-size:18px}}

#adminButton,#adminNav,#admin{display:none!important}#signedInAs,button[onclick="logout()"]{display:none!important}

.workflow-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0 22px}.workflow-step{position:relative;padding:20px;border:1px solid #2a3a54;border-radius:17px;background:linear-gradient(145deg,#142139,#101827);min-width:0}.workflow-number{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#243b50;color:var(--mint);font-weight:850;margin-bottom:14px}.workflow-step h3{margin:0 0 7px}.workflow-step p{margin:0;color:var(--muted);font-size:13px}.method-chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.method-chip{padding:7px 10px;border:1px solid #344663;border-radius:999px;background:#131f32;color:#d5e2f6;font-size:12px}.project-note{border-left:3px solid var(--mint);padding:12px 15px;background:#10231f;border-radius:0 12px 12px 0;color:#c7e7dd;font-size:13px;margin-top:14px}
@media(max-width:900px){.workflow-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:520px){.workflow-grid{grid-template-columns:1fr}.hero{grid-template-columns:1fr}.hero-art{display:none}.hero h2{font-size:32px}.hero-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.section-heading{align-items:flex-start;flex-direction:column}}
/* Professional visual polish: layered research-grade background and calmer surfaces */
:root{
  --bg:#070d18;
  --surface:#101a2b;
  --surface2:#16243a;
  --line:#2a3b55;
  --muted:#aebbd0;
  --text:#f4f7ff;
  --mint:#91ead0;
  --blue:#9bbcff;
  --radius:18px
}
html{background:#070d18}
body{
  background:
    radial-gradient(ellipse at 12% 0%,rgba(57,105,171,.22),transparent 36%),
    radial-gradient(ellipse at 92% 16%,rgba(84,77,156,.16),transparent 32%),
    radial-gradient(ellipse at 48% 100%,rgba(39,110,111,.10),transparent 42%),
    linear-gradient(145deg,#070d18 0%,#0a1220 48%,#080e1a 100%);
  background-attachment:fixed;
}
header{border-bottom-color:rgba(143,171,211,.18)}
.nav{
  background:rgba(12,21,36,.88);
  border-color:rgba(139,164,202,.22);
  box-shadow:0 16px 42px rgba(0,0,0,.22);
}
.hero{
  background:
    radial-gradient(ellipse at 92% 0%,rgba(121,151,255,.16),transparent 38%),
    linear-gradient(118deg,rgba(22,42,68,.98),rgba(16,28,48,.98) 58%,rgba(27,27,56,.98));
  border-color:rgba(139,171,216,.30);
  box-shadow:0 28px 80px rgba(0,0,0,.25),inset 0 1px 0 rgba(255,255,255,.035);
}
.card,section{
  background:linear-gradient(150deg,rgba(19,31,51,.96),rgba(12,21,36,.97));
  border-color:rgba(132,158,197,.20);
  box-shadow:0 12px 32px rgba(0,0,0,.13),inset 0 1px 0 rgba(255,255,255,.025);
}
.feature-card{
  background:linear-gradient(145deg,rgba(19,31,51,.92),rgba(14,24,41,.96));
  border-color:rgba(132,158,197,.19);
}
.card-icon{background:linear-gradient(145deg,#243750,#1b2a42);border:1px solid rgba(151,182,226,.12)}
button,.btn,select,input,textarea{
  background-color:rgba(18,30,50,.94);
  border-color:rgba(133,160,201,.30);
}
button:hover,.btn:hover{border-color:var(--mint);box-shadow:0 5px 18px rgba(145,234,208,.08)}
.tablewrap{border-color:rgba(132,158,197,.22)}
table{background:rgba(10,18,31,.78)}
th{background:rgba(24,38,60,.95)}
td,th{border-bottom-color:rgba(132,158,197,.15)}
.site-footer{border-top-color:rgba(143,171,211,.18)}
.bottom-nav{
  background:rgba(13,23,39,.92);
  border-color:rgba(139,164,202,.26);
}
@media(prefers-reduced-motion:no-preference){
  .card,.feature-card,section{transition:border-color .2s ease,box-shadow .2s ease}
  .card:hover,.feature-card:hover{border-color:rgba(145,234,208,.30);box-shadow:0 16px 36px rgba(0,0,0,.19)}
}



/* Cognitive Analysis brain-network visual */
.brain-network-feature{position:relative;display:grid;grid-template-columns:minmax(220px,.72fr) minmax(0,1.55fr);gap:22px;align-items:center;overflow:hidden;margin:0 0 22px;padding:25px;border:1px solid #28456d;border-radius:22px;background:radial-gradient(ellipse at 78% 45%,rgba(37,91,180,.25),transparent 48%),linear-gradient(125deg,#08162c 0%,#0b1730 48%,#101735 100%);box-shadow:0 20px 55px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.035)}
.brain-network-copy{position:relative;z-index:2}.brain-eyebrow{display:inline-block;margin-bottom:12px;color:#67dfff;font-size:10px;font-weight:800;letter-spacing:1.7px}.brain-network-copy h2{margin:0 0 10px!important;font-size:clamp(24px,3vw,34px);line-height:1.1;color:#edf6ff}.brain-network-copy p{max-width:330px;margin:0;color:#a9bfde;line-height:1.65;font-size:13px}.brain-tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:19px}.brain-tags span{display:flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid rgba(91,153,220,.22);border-radius:999px;background:rgba(12,37,72,.65);color:#c7ddfb;font-size:10px}.brain-tags i,.pulse-dot{width:6px;height:6px;border-radius:50%;background:#48dcff;box-shadow:0 0 10px #48dcff}.brain-visual{position:relative;min-width:0;min-height:280px;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1px solid rgba(79,142,221,.17);border-radius:17px;background:radial-gradient(ellipse at 50% 48%,rgba(28,85,170,.25),transparent 58%),linear-gradient(135deg,rgba(2,12,31,.76),rgba(9,20,48,.7))}.brain-svg{position:relative;z-index:1;width:100%;max-width:600px;height:auto;overflow:visible;filter:drop-shadow(0 0 12px rgba(43,151,255,.14));animation:brainFloat 6s ease-in-out infinite}.brain-orbit{position:absolute;left:50%;top:49%;width:74%;height:64%;border:1px solid rgba(77,157,255,.13);border-radius:50%;transform:translate(-50%,-50%) rotate(-18deg);box-shadow:0 0 30px rgba(37,127,255,.06)}.orbit-two{width:60%;height:80%;transform:translate(-50%,-50%) rotate(37deg);border-color:rgba(184,102,255,.14)}.brain-caption{position:absolute;z-index:2;left:15px;bottom:13px;display:flex;align-items:center;gap:8px;color:#c3d9fa;font-size:10px;letter-spacing:.2px}.caption-divider{color:#536f9b}.pulse-dot{animation:brainPulse 1.8s ease-in-out infinite}.brain-network-feature+section{margin-top:0}@keyframes brainFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}@keyframes brainPulse{0%,100%{opacity:1;box-shadow:0 0 8px #48dcff}50%{opacity:.45;box-shadow:0 0 16px #48dcff}}@media(max-width:760px){.brain-network-feature{grid-template-columns:1fr;padding:19px;gap:15px}.brain-network-copy p{max-width:none}.brain-visual{min-height:230px}.brain-svg{width:108%}.brain-caption{font-size:9px;left:10px;bottom:9px}}@media(prefers-reduced-motion:reduce){.brain-svg,.pulse-dot{animation:none}}

/* Dashboard layout inspired by the approved reference */
body{background:radial-gradient(ellipse at 65% 0%,rgba(17,77,155,.20),transparent 40%),linear-gradient(135deg,#020b1d,#06142a 60%,#030b1a);background-attachment:fixed}
#appShell{max-width:none!important;width:100%;padding:0!important;margin:0!important}
#appShell>header{position:fixed;z-index:60;left:0;right:0;top:0;height:78px;padding:12px 28px;background:rgba(3,13,32,.96);border-bottom:1px solid #17355e;backdrop-filter:blur(18px)}
#appShell>header .brand-mark{background:transparent;color:#40d7ff;box-shadow:none;font-size:30px}
#appShell>header .brand h1{font-size:20px;letter-spacing:-.5px}
#appShell>header .brand p{font-size:12px;color:#8eadd8}
#appShell>.nav{position:fixed;z-index:55;left:0;top:78px;bottom:0;width:243px;margin:0;padding:22px 12px;display:flex;flex-direction:column;flex-wrap:nowrap;gap:5px;border:0;border-right:1px solid #17355e;border-radius:0;background:rgba(3,14,33,.97);box-shadow:none;align-items:stretch}
#appShell>.nav button{display:flex;align-items:center;text-align:left;width:100%;min-height:48px;padding:12px 16px;border-radius:10px;font-size:14px;color:#c3d8f5}
#appShell>.nav button.active{background:linear-gradient(110deg,#0c3d9d,#08296e);color:white;box-shadow:none}
#appShell>#error,#appShell>#admin{margin-left:243px}
#appShell>#overview,#appShell>#network,#appShell>#patients,#appShell>#analytics,#appShell>#longitudinal,#appShell>#research,#appShell>#mmse-moca{display:block;max-width:none;margin:0 0 0 243px;padding:94px 24px 32px;min-height:100vh}
#appShell>#overview.hidden,#appShell>#network.hidden,#appShell>#patients.hidden,#appShell>#analytics.hidden,#appShell>#longitudinal.hidden,#appShell>#research.hidden,#appShell>#mmse-moca.hidden{display:none!important}
#overview>.hero{display:grid;grid-template-columns:minmax(245px,.88fr) minmax(300px,1.15fr) minmax(220px,.72fr);gap:18px;align-items:center;min-height:365px;margin-bottom:18px;padding:22px 24px;border-radius:12px;border:1px solid #153b70;background:linear-gradient(110deg,rgba(3,20,48,.98),rgba(4,18,43,.97));box-shadow:none}
#overview>.hero:after{display:none}
#overview>.hero>div:first-child{grid-column:1;grid-row:1}
#overview>.hero .eyebrow{display:inline-block;color:#a6dfff;letter-spacing:.3px;background:#082f70;padding:8px 12px;border-radius:8px}
#overview>.hero h2{font-size:clamp(27px,2.5vw,38px);line-height:1.12;letter-spacing:-1px;margin:18px 0 12px}
#overview>.hero h2 .hero-accent{color:#287bff}
#overview>.hero p{font-size:14px;color:#b4cbed;line-height:1.7}
#overview>.hero .hero-kpis{display:none}
#overview>.hero .hero-actions{margin-top:20px}
#overview>.hero .hero-actions button{font-size:12px;border-radius:10px;padding:12px 16px}
#overview>.hero .hero-art{display:none}
#overview>.brain-network-feature{display:none!important}
#overview>.hero .brain-visual{grid-column:2;grid-row:1;display:flex;min-width:0;min-height:320px;height:100%;position:relative;align-items:center;justify-content:center;overflow:hidden;background:radial-gradient(ellipse at center,rgba(0,96,255,.18),transparent 68%);border:0;border-radius:0;padding:0}
#overview>.hero .brain-svg{width:100%;max-width:570px;height:auto;filter:drop-shadow(0 0 18px rgba(0,132,255,.55));animation:brainGlowPulse 4s ease-in-out infinite}
#overview>.hero .brain-orbit{position:absolute;border:1px solid rgba(40,123,255,.25);border-radius:50%;width:92%;height:76%;transform:rotate(-18deg);pointer-events:none}
#overview>.hero .orbit-two{width:82%;height:92%;transform:rotate(30deg);border-color:rgba(121,84,255,.24)}
#overview>.hero .brain-caption{position:absolute;bottom:6px;left:50%;transform:translateX(-50%);white-space:nowrap;color:#8eb8ed;font-size:10px;letter-spacing:.2px}
#overview>.hero .brain-network-copy{display:none}
#overview>.hero .hero-feature-rail{grid-column:3;grid-row:1;display:flex;flex-direction:column;gap:9px;min-width:0}
#overview>.hero .hero-feature{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid #15355f;border-radius:13px;background:linear-gradient(120deg,rgba(8,35,76,.96),rgba(4,23,53,.98));min-height:72px}
#overview>.hero .hero-feature-icon{display:grid;place-items:center;flex:0 0 48px;height:48px;border-radius:12px;background:linear-gradient(140deg,#073c91,#0753a9);font-size:22px;color:#42d5ff}
#overview>.hero .hero-feature:nth-child(2) .hero-feature-icon{background:linear-gradient(140deg,#38206e,#552b94);color:#d2a7ff}
#overview>.hero .hero-feature:nth-child(3) .hero-feature-icon{background:linear-gradient(140deg,#064e5a,#087b8b);color:#5cf1e2}
#overview>.hero .hero-feature:nth-child(4) .hero-feature-icon{background:linear-gradient(140deg,#542d39,#793c4b);color:#ffb36c}
#overview>.hero .hero-feature b{display:block;font-size:12px;color:#f3f7ff;margin-bottom:2px}
#overview>.hero .hero-feature small{display:block;font-size:11px;line-height:1.45;color:#a8c3e8}
#overview>.cards{margin:0 0 16px;gap:14px}
#overview>.cards .card{display:grid;grid-template-columns:48px 1fr;align-content:center;column-gap:12px;min-height:112px;padding:17px;border:1px solid #15355f;border-radius:12px;background:linear-gradient(140deg,#061a39,#031329);box-shadow:none}
#overview>.cards .card .card-icon{grid-row:1 / span 3;width:48px;height:48px;border-radius:12px;background:linear-gradient(140deg,#0a3b86,#0751a4);color:#49d8ff}
#overview>.cards .card strong{font-size:27px;margin:0}
#overview>.cards .card small{font-size:10px}
#overview .section-heading{margin:20px 0 10px}
#overview .feature-card,#overview .workflow-step,#overview section{border-color:#15345b;background:linear-gradient(145deg,rgba(4,22,49,.98),rgba(3,16,36,.98));box-shadow:none}
#overview .brain-network-feature{margin:0}
#overview .feature-card{border-radius:12px}
#overview .two{gap:14px}
#overview .card, #overview section{border-radius:12px}
#overview .hero-feature-rail{align-self:stretch;justify-content:center}
@keyframes brainGlowPulse{0%,100%{filter:drop-shadow(0 0 12px rgba(0,132,255,.42))}50%{filter:drop-shadow(0 0 26px rgba(55,115,255,.85))}}
@media(max-width:1050px){#overview>.hero{grid-template-columns:minmax(220px,.9fr) minmax(240px,1fr)}#overview>.hero .hero-feature-rail{grid-column:1 / -1;grid-row:2;display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}#overview>.hero .brain-visual{grid-column:2;grid-row:1}}
@media(max-width:700px){#appShell>header{height:70px;padding:9px 12px}#appShell>header .brand h1{font-size:15px}#appShell>header .brand p{display:none}#appShell>.nav{top:auto;bottom:0;left:0;right:0;width:auto;height:70px;padding:6px 3px;flex-direction:row;overflow-x:auto;border-top:1px solid #17355e;border-right:0;gap:2px}#appShell>.nav button{flex:1;min-width:72px;min-height:52px;justify-content:center;text-align:center;display:flex;flex-direction:column;padding:6px 2px;font-size:10px;white-space:normal}#appShell>#overview,#appShell>#network,#appShell>#patients,#appShell>#analytics,#appShell>#longitudinal,#appShell>#research,#appShell>#mmse-moca{margin-left:0;padding:84px 12px 90px}#overview>.hero{grid-template-columns:1fr;gap:8px;padding:18px;min-height:0}#overview>.hero>div:first-child{grid-column:1;grid-row:1}#overview>.hero .brain-visual{grid-column:1;grid-row:2;min-height:245px}#overview>.hero .hero-feature-rail{grid-column:1;grid-row:3;grid-template-columns:1fr 1fr}#overview>.hero .hero-feature{padding:9px;min-height:68px}#overview>.hero .hero-feature-icon{flex-basis:36px;height:36px;font-size:17px}#overview>.hero .hero-feature small{font-size:10px}#overview>.cards{grid-template-columns:repeat(2,minmax(0,1fr))}#overview .two{grid-template-columns:1fr}}

/* Animated neural ambience: home page only; content and layout stay above it */
#psn-neural-bg{position:fixed!important;inset:0;width:100vw;height:100vh;z-index:0!important;pointer-events:none;opacity:0;transition:opacity .7s ease;mix-blend-mode:screen}
body.psn-home-active #psn-neural-bg{opacity:.38}
body{background-image:radial-gradient(ellipse at 18% 20%,rgba(0,112,255,.13),transparent 42%),radial-gradient(ellipse at 82% 75%,rgba(0,225,255,.08),transparent 38%),radial-gradient(ellipse at 50% -10%,#1a3150 0,transparent 42%)}
body.psn-home-active:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(circle at 18% 32%,rgba(0,125,255,.09),transparent 25%),radial-gradient(circle at 76% 68%,rgba(25,75,255,.08),transparent 28%);animation:psnAtmosphere 12s ease-in-out infinite alternate}
@keyframes psnAtmosphere{from{opacity:.45;transform:scale(1)}to{opacity:1;transform:scale(1.04)}}
@media(prefers-reduced-motion:reduce){#psn-neural-bg,body.psn-home-active:before{animation:none!important;transition:none!important}}

/* Make the home cognitive-analysis brain a large luminous focal point */
#overview .brain-visual{min-height:320px;background:radial-gradient(ellipse at 50% 48%,rgba(0,114,255,.34),transparent 63%),linear-gradient(135deg,rgba(1,12,32,.5),rgba(5,18,48,.25));border-color:rgba(36,133,255,.3)}
#overview .brain-svg{width:112%;max-width:660px;filter:drop-shadow(0 0 18px rgba(0,132,255,.42)) drop-shadow(0 0 34px rgba(85,55,255,.18));animation:brainFloat 6s ease-in-out infinite,brainAura 4.2s ease-in-out infinite}
#overview .brain-visual:before{content:"";position:absolute;width:78%;height:78%;border-radius:50%;background:radial-gradient(circle,rgba(0,105,255,.22),rgba(35,67,255,.07) 48%,transparent 72%);filter:blur(12px);animation:brainAura 5s ease-in-out infinite;pointer-events:none}
@keyframes brainAura{0%,100%{opacity:.55;transform:scale(.96)}50%{opacity:1;transform:scale(1.06)}}
@media(max-width:700px){#overview .brain-visual{min-height:260px}#overview .brain-svg{width:115%}}

/* Living neural brain: animated synapses, firing nodes, and breathing electric glow */
#overview .brain-visual{min-height:340px;isolation:isolate;background:radial-gradient(ellipse at 50% 47%,rgba(0,144,255,.28),transparent 61%),linear-gradient(145deg,rgba(1,12,32,.72),rgba(7,18,46,.54))}
#overview .brain-svg{width:116%;max-width:700px;filter:drop-shadow(0 0 17px rgba(0,170,255,.42)) drop-shadow(0 0 36px rgba(78,64,255,.25));animation:brainFloat 6s ease-in-out infinite,brainBreathe 3.8s ease-in-out infinite}
#overview .brain-svg g[fill="none"] path{stroke-dasharray:8 10;animation:neuralSignal 7s linear infinite}
#overview .brain-svg g[fill="none"] path:nth-child(2n){animation-duration:9s;animation-direction:reverse}
#overview .brain-svg g[fill="#b8f7ff"] circle{animation:neuronFire 2.4s ease-in-out infinite;transform-box:fill-box;transform-origin:center}
#overview .brain-svg g[fill="#b8f7ff"] circle:nth-child(3n){animation-delay:-.8s}
#overview .brain-svg g[fill="#b8f7ff"] circle:nth-child(4n){animation-delay:-1.5s}
#overview .brain-svg g[fill="#dcaaff"] circle{animation:neuronFireViolet 3s ease-in-out infinite;transform-box:fill-box;transform-origin:center}
#overview .brain-svg g[fill="#dcaaff"] circle:nth-child(odd){animation-delay:-1.2s}
#overview .brain-visual:before{content:"";position:absolute;z-index:0;inset:12%;border-radius:50%;background:radial-gradient(ellipse,rgba(0,136,255,.18),rgba(74,53,255,.07) 46%,transparent 72%);filter:blur(16px);animation:brainBreathe 4s ease-in-out infinite;pointer-events:none}
#overview .brain-orbit{border-color:rgba(56,177,255,.27);box-shadow:0 0 32px rgba(0,132,255,.12);animation:orbitBreathe 7s ease-in-out infinite}
#overview .orbit-two{border-color:rgba(167,100,255,.23);animation-delay:-3.5s}
@keyframes neuralSignal{to{stroke-dashoffset:-180}}
@keyframes neuronFire{0%,100%{opacity:.72;scale:.85;filter:drop-shadow(0 0 2px #45dfff)}50%{opacity:1;scale:1.28;filter:drop-shadow(0 0 8px #7ff6ff)}}
@keyframes neuronFireViolet{0%,100%{opacity:.65;scale:.9;filter:drop-shadow(0 0 2px #9d78ff)}50%{opacity:1;scale:1.2;filter:drop-shadow(0 0 9px #c3a4ff)}}
@keyframes brainBreathe{0%,100%{opacity:.55;transform:scale(.96)}50%{opacity:1;transform:scale(1.045)}}
@keyframes orbitBreathe{0%,100%{opacity:.5}50%{opacity:1}}
@media(max-width:700px){#overview .brain-visual{min-height:270px}#overview .brain-svg{width:118%}}
@media(prefers-reduced-motion:reduce){#overview .brain-svg,#overview .brain-svg g path,#overview .brain-svg circle,#overview .brain-orbit,#overview .brain-visual:before{animation:none!important}}

/* Premium understated neural-flow sidebar */
@media(min-width:951px){
  main{max-width:none;margin:0;padding:24px 34px 110px 286px}
  header{min-height:70px}
  .nav[aria-label="Main navigation"]{
    position:fixed;z-index:80;left:16px;top:16px;bottom:16px;width:238px;
    display:flex;flex-direction:column;align-items:stretch;justify-content:flex-start;
    gap:8px;padding:20px 13px 18px;overflow:hidden;isolation:isolate;
    border:1px solid rgba(117,177,201,.22);border-radius:25px;
    background:linear-gradient(155deg,rgba(13,25,41,.985),rgba(11,24,39,.985) 52%,rgba(12,29,43,.99));
    box-shadow:0 24px 68px rgba(0,0,0,.28),inset 0 1px 0 rgba(225,245,255,.07),inset 0 0 34px rgba(57,143,176,.055);
  }
  .nav[aria-label="Main navigation"]:before{
    content:"";position:absolute;inset:0;z-index:-2;pointer-events:none;
    background:
      radial-gradient(ellipse at 16% 18%,rgba(54,139,190,.13),transparent 40%),
      radial-gradient(ellipse at 90% 58%,rgba(34,160,157,.10),transparent 42%),
      linear-gradient(125deg,transparent 20%,rgba(104,188,219,.025) 44%,rgba(113,218,215,.07) 49%,transparent 57%);
    background-size:100% 100%,100% 100%,240% 100%;
    animation:psnNeuralAmbient 12s ease-in-out infinite;
  }
  .nav[aria-label="Main navigation"]:after{
    content:"";position:absolute;z-index:-1;pointer-events:none;inset:-10% -52%;
    opacity:.55;
    background:
      radial-gradient(ellipse at 22% 26%,rgba(64,163,211,.16),transparent 27%),
      linear-gradient(112deg,transparent 24%,rgba(67,151,205,.035) 35%,rgba(106,201,224,.24) 46%,rgba(92,231,222,.13) 49%,transparent 58%),
      linear-gradient(112deg,transparent 51%,rgba(63,150,193,.085) 58%,rgba(77,203,195,.16) 62%,transparent 70%),
      repeating-linear-gradient(132deg,transparent 0 68px,rgba(101,205,224,.055) 69px,rgba(101,205,224,.055) 70px,transparent 72px 136px);
    background-size:100% 100%,220% 100%,220% 100%,100% 240%;
    filter:blur(.35px);
    transform:translate3d(-9%,0,0) skewY(-5deg);
    animation:psnSignalDrift 11s ease-in-out infinite,psnFlowCurrent 15s linear infinite;
  }
  @keyframes psnNeuralAmbient{
    0%,100%{background-position:0 0,0 0,0 0;opacity:.7}
    50%{background-position:0 0,0 0,100% 0;opacity:1}
  }
  @keyframes psnSignalDrift{
    0%{transform:translate3d(-9%,0,0) skewY(-5deg);background-position:0 0,0 0,100% 0,0 0;opacity:.48}
    50%{transform:translate3d(5%,-.5%,0) skewY(2deg);background-position:0 0,100% 0,0 0,0 100%;opacity:.82}
    100%{transform:translate3d(-9%,0,0) skewY(-5deg);background-position:0 0,0 0,100% 0,0 0;opacity:.48}
  }
  @keyframes psnFlowCurrent{
    0%{background-position:0 0,0 0,100% 0,0 0}
    100%{background-position:0 0,100% 0,0 0,0 100%}
  }
  .nav[aria-label="Main navigation"] button{
    position:relative;z-index:1;flex:0 0 auto;width:100%;min-height:47px;text-align:left;
    display:flex;align-items:center;padding:12px 14px;border:1px solid rgba(133,177,203,.075);border-radius:14px;
    background:rgba(22,39,57,.56);color:#bdcede;font-size:13px;letter-spacing:.12px;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.02);
    transition:background .32s ease,border-color .32s ease,color .32s ease,transform .32s ease,box-shadow .32s ease;
  }
  .nav[aria-label="Main navigation"] button:hover{
    background:rgba(39,72,91,.43);border-color:rgba(100,190,208,.18);color:#effaff;
    transform:translateX(2px);box-shadow:0 5px 16px rgba(0,0,0,.09),inset 0 1px 0 rgba(255,255,255,.035);
  }
  .nav[aria-label="Main navigation"] button.active{
    color:#e5f7fc;background:linear-gradient(105deg,rgba(37,121,151,.28),rgba(36,113,129,.24) 58%,rgba(43,72,99,.3));
    background-size:200% 100%;
    border-color:rgba(103,192,208,.28);
    box-shadow:inset 2px 0 0 rgba(103,202,216,.78),0 5px 20px rgba(0,0,0,.11),inset 0 1px 0 rgba(255,255,255,.04);
    animation:psnActiveCurrent 7s ease-in-out infinite;
  }
  @keyframes psnActiveCurrent{0%,100%{background-position:0 50%;box-shadow:inset 2px 0 0 rgba(103,202,216,.68),0 5px 18px rgba(0,0,0,.09)}50%{background-position:100% 50%;box-shadow:inset 2px 0 0 rgba(103,202,216,.95),0 0 22px rgba(54,164,184,.10)}}
  .nav[aria-label="Main navigation"] button.active:after{
    content:"";width:5px;height:5px;border-radius:50%;margin-left:auto;
    background:#82d6df;box-shadow:0 0 8px rgba(105,210,222,.42);
    animation:psnSignalPulse 5s ease-in-out infinite;
  }
  @keyframes psnSignalPulse{0%,100%{opacity:.55;transform:scale(.9)}50%{opacity:.9;transform:scale(1.04)}}
  .nav[aria-label="Main navigation"] button#adminNav{margin-top:auto}
}
@media(max-width:950px){
  .nav[aria-label="Main navigation"]{display:none}
  main{padding-left:18px!important}
}
@media(prefers-reduced-motion:reduce){
  .nav[aria-label="Main navigation"]:before,.nav[aria-label="Main navigation"]:after,.nav[aria-label="Main navigation"] button.active:after,.nav[aria-label="Main navigation"] button.active{animation:none!important}
}
</style></head><body><div id="authScreen" style="display:none;align-items:center;justify-content:center;padding:18px;overflow:auto"><section style="width:min(440px,100%);margin:auto"><div style="font-size:12px;letter-spacing:2px;color:var(--mint);font-weight:700">PSN RESEARCH HUB</div><h1 id="authTitle" style="margin:8px 0 4px">Welcome to PSN</h1><p id="authSubtitle" class="muted">Sign in to your Study Analyst Workspace.</p><div class="nav"><button id="loginMode" class="primary" type="button" onclick="authMode('login')">Sign in</button><button id="registerMode" type="button" onclick="authMode('register')">Create account</button></div><form id="authForm" onsubmit="submitAuth(event)"><label id="nameWrap" class="hidden">Full name<br><input name="name" minlength="2" maxlength="80" autocomplete="name" style="width:100%;margin:6px 0 12px"></label><label>Email<br><input name="email" type="email" required autocomplete="email" style="width:100%;margin:6px 0 12px"></label><label>Password<br><input name="password" type="password" minlength="10" required autocomplete="current-password" style="width:100%;margin:6px 0 12px"></label><button id="authSubmit" class="primary" type="submit" style="width:100%">Sign in</button><p id="authMessage" class="muted" role="status"></p></form><p id="adminBackLink" class="hidden" style="text-align:center;margin:14px 0 0"><a href="/" style="color:var(--blue)">← Back to PSN Research Hub</a></p><small>Use only synthetic demo records. Do not upload real patient data to this prototype.</small></section></div><main id="appShell" style="display:block"><header><div class="brand"><div class="brand-mark" aria-hidden="true">✳</div><div><h1>Patient Similarity Network</h1><p>Cognitive insights · Patient profile analytics</p></div></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span id="signedInAs" class="muted"></span><button id="adminButton" class="hidden" onclick="tab('admin')">Admin Console</button><button onclick="logout()">Sign out</button></div></header><nav class="nav" aria-label="Main navigation"><button class="active" data-tab="overview">⌂ &nbsp; Home</button><button data-tab="network">◎ &nbsp; Patient Network</button><button data-tab="patients">♙ &nbsp; Patient Explorer</button><button data-tab="analytics">◈ &nbsp; Analytics</button><button data-tab="longitudinal">↗ &nbsp; Follow-ups</button><button data-tab="research">▤ &nbsp; Research Lab</button><button data-tab="mmse-moca">＋ &nbsp; Assessments</button><button id="adminNav" class="hidden" data-tab="admin">Admin Console</button></nav><div id="error" class="notice hidden"></div><div id="admin" class="hidden"><section class="admin-hero"><div><div class="eyebrow">CONTROL CENTER / ACCESS MANAGEMENT</div><h2>PSN Admin Console</h2><p class="muted">Manage accounts, review roles, and control access to the research workspace.</p></div><div class="admin-hero-actions"><span class="secure-chip">● Admin session</span><button class="primary" onclick="loadAdminUsers()">↻ Refresh</button></div></section><div id="adminSummary" class="admin-stats"></div><section class="admin-directory"><div class="directory-head"><div><h2>Account directory</h2><p class="muted">Search registered users and update their access level.</p></div><span id="adminCountLabel" class="count-pill">Loading…</span></div><div class="toolbar admin-tools"><input id="adminSearch" type="search" placeholder="Search name, email, or role…" oninput="loadAdminUsers()" aria-label="Search accounts"></div><div id="adminUsers" class="admin-users"><p class="muted">Loading accounts…</p></div></section><p class="admin-footnote">Security note: keep administrator access limited to trusted project maintainers. Demo data only; this console is not for real patient records.</p></div><div id="overview"><section class="hero"><div><div class="eyebrow">Cognitive analytics workspace</div><h2>Understand the connections behind cognitive profiles.</h2><p>Explore patient similarity, compare cognitive domains, follow score changes over time, and turn structured assessments into clear research insights.</p><div class="hero-actions"><button class="primary" onclick="tab('network')">Explore the network &nbsp; ↗</button><button onclick="tab('patients')">Open patient explorer</button></div><div class="hero-kpis"><div class="hero-kpi"><strong id="heroTotal">—</strong><span>Patient profiles</span></div><div class="hero-kpi"><strong id="heroCohorts">3</strong><span>Cohort categories</span></div><div class="hero-kpi"><strong>7</strong><span>Cognitive domains</span></div></div></div><div class="hero-art" aria-hidden="true"><svg class="network-art" viewBox="0 0 340 270"><defs><linearGradient id="nodeGlow" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#8ce6c6"/><stop offset="1" stop-color="#9db6ff"/></linearGradient></defs><g stroke="#91aeea" stroke-opacity=".42" stroke-width="1.6"><path d="M50 60 125 35 195 68 270 40 300 105 245 160 285 220 190 235 125 190 50 210 30 130 50 60 125 35 125 190 195 68 190 235 245 160 125 35 270 40 245 160 300 105 195 68 285 220 50 210 125 190 30 130 195 68"/></g><g fill="url(#nodeGlow)"><circle cx="50" cy="60" r="9"/><circle cx="125" cy="35" r="7"/><circle cx="195" cy="68" r="12"/><circle cx="270" cy="40" r="8"/><circle cx="300" cy="105" r="10"/><circle cx="245" cy="160" r="14"/><circle cx="285" cy="220" r="7"/><circle cx="190" cy="235" r="10"/><circle cx="125" cy="190" r="12"/><circle cx="50" cy="210" r="8"/><circle cx="30" cy="130" r="11"/></g><g fill="#eaf4ff" fill-opacity=".9"><circle cx="160" cy="125" r="20"/><circle cx="160" cy="125" r="29" fill="none" stroke="#8ce6c6" stroke-opacity=".55"/></g></svg></div></section>
<section class="brain-network-feature"><div class="brain-network-copy"><span class="brain-eyebrow">COGNITIVE ANALYSIS WORKSPACE</span><h2>Brain Network</h2><p>Explore connected cognitive regions through a glowing neural network visualization.</p><div class="brain-tags"><span><i></i> Neural connections</span><span><i></i> Cognitive patterns</span></div><div class="brain-tags"><span><i></i> Similarity analysis</span><span><i></i> K-means clustering</span><span><i></i> Graph metrics</span></div><div class="hero-actions" style="margin-top:18px"><button class="primary" onclick="tab('analytics')">Open Cognitive Analysis →</button><button onclick="tab('network')">Explore Patient Network</button></div></div><div class="brain-visual" role="img" aria-label="Glowing blue and violet brain neural network illustration"><div class="brain-orbit orbit-one"></div><div class="brain-orbit orbit-two"></div><svg class="brain-svg" viewBox="0 0 560 360" aria-hidden="true"><defs><radialGradient id="brainCore"><stop offset="0" stop-color="#2ce8ff" stop-opacity=".38"/><stop offset=".65" stop-color="#1678ff" stop-opacity=".14"/><stop offset="1" stop-color="#06142d" stop-opacity="0"/></radialGradient><linearGradient id="cortex" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#37efff"/><stop offset=".42" stop-color="#248cff"/><stop offset=".72" stop-color="#6367ff"/><stop offset="1" stop-color="#e27cff"/></linearGradient><filter id="cortexGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="4" result="blur"/><feColorMatrix in="blur" type="matrix" values="0 0 0 0 .05 0 0 0 0 .48 0 0 0 0 1 0 0 0 .9 0" result="blueblur"/><feMerge><feMergeNode in="blueblur"/><feMergeNode in="SourceGraphic"/></feMerge></filter><filter id="nodeHalo"><feGaussianBlur stdDeviation="2.6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><ellipse cx="280" cy="178" rx="250" ry="165" fill="url(#brainCore)"/><g fill="none" stroke="url(#cortex)" stroke-linecap="round" stroke-linejoin="round" filter="url(#cortexGlow)"><path stroke-width="3.2" d="M278 67 C263 42 229 28 199 39 C179 21 147 36 138 57 C106 54 82 79 88 106 C60 126 69 158 88 174 C71 198 90 224 113 230 C114 258 145 275 169 262 C191 285 219 274 237 258 C253 268 269 251 278 235"/><path stroke-width="3.2" d="M282 67 C297 42 331 28 361 39 C381 21 413 36 422 57 C454 54 478 79 472 106 C500 126 491 158 472 174 C489 198 470 224 447 230 C446 258 415 275 391 262 C369 285 341 274 323 258 C307 268 291 251 282 235"/><path stroke-width="2.3" d="M278 68 C253 60 236 75 240 94 C216 102 215 124 231 137 C208 152 218 177 238 184 C224 203 239 222 258 220 L278 235 M282 68 C307 60 324 75 320 94 C344 102 345 124 329 137 C352 152 342 177 322 184 C336 203 321 222 302 220 L282 235"/><path stroke-width="2" d="M139 58 C157 64 166 78 157 94 C141 109 151 124 172 125 C185 139 176 155 159 162 C144 176 154 194 174 197 C186 211 176 229 165 239 M199 40 C194 58 208 70 224 70 C241 77 240 91 227 102 M91 107 C111 112 120 128 110 144 C103 157 113 169 130 169 M113 230 C130 221 143 225 150 240 M169 262 C177 246 197 243 210 255 M421 58 C403 64 394 78 403 94 C419 109 409 124 388 125 C375 139 384 155 401 162 C416 176 406 194 386 197 C374 211 384 229 395 239 M361 40 C366 58 352 70 336 70 C319 77 320 91 333 102 M469 107 C449 112 440 128 450 144 C457 157 447 169 430 169 M447 230 C430 221 417 225 410 240 M391 262 C383 246 363 243 350 255"/><path stroke-width="1.5" opacity=".85" d="M278 67 L282 235 M157 94 L190 105 L227 102 L240 94 M172 125 L204 137 L231 137 M159 162 L197 173 L238 184 M174 197 L208 207 L258 220 M165 239 L198 229 L237 258 M403 94 L370 105 L333 102 M388 125 L356 137 L329 137 M401 162 L363 173 L322 184 M386 197 L352 207 L302 220 M395 239 L362 229 L323 258"/></g><g fill="none" stroke="#54dfff" stroke-width="1.15" opacity=".7"><path d="M68 88 L88 106 L110 144 L130 169 L113 230 L150 240 L169 262 L210 255 L237 258 L278 235"/><path d="M492 88 L472 106 L450 144 L430 169 L447 230 L410 240 L391 262 L350 255 L323 258 L282 235"/><path d="M105 65 L138 57 L157 94 L190 105 L204 137 L197 173 L208 207 L198 229 L210 255"/><path d="M455 65 L422 57 L403 94 L370 105 L356 137 L363 173 L352 207 L362 229 L350 255"/><path d="M199 40 L224 70 L227 102 L204 137 L197 173 M361 40 L336 70 L333 102 L356 137 L363 173"/></g><g fill="#b8f7ff" filter="url(#nodeHalo)"><circle cx="138" cy="57" r="4"/><circle cx="157" cy="94" r="4"/><circle cx="190" cy="105" r="4.5"/><circle cx="172" cy="125" r="4"/><circle cx="204" cy="137" r="5"/><circle cx="159" cy="162" r="4"/><circle cx="197" cy="173" r="4.5"/><circle cx="174" cy="197" r="4"/><circle cx="208" cy="207" r="4"/><circle cx="165" cy="239" r="4"/><circle cx="198" cy="229" r="4"/><circle cx="210" cy="255" r="4"/><circle cx="240" cy="94" r="5"/><circle cx="231" cy="137" r="4.5"/><circle cx="238" cy="184" r="5"/><circle cx="258" cy="220" r="4"/><circle cx="278" cy="67" r="5"/><circle cx="278" cy="235" r="5"/><circle cx="422" cy="57" r="4"/><circle cx="403" cy="94" r="4"/><circle cx="370" cy="105" r="4.5"/><circle cx="388" cy="125" r="4"/><circle cx="356" cy="137" r="5"/><circle cx="401" cy="162" r="4"/><circle cx="363" cy="173" r="4.5"/><circle cx="386" cy="197" r="4"/><circle cx="352" cy="207" r="4"/><circle cx="395" cy="239" r="4"/><circle cx="362" cy="229" r="4"/><circle cx="350" cy="255" r="4"/><circle cx="320" cy="94" r="5"/><circle cx="329" cy="137" r="4.5"/><circle cx="322" cy="184" r="5"/><circle cx="302" cy="220" r="4"/></g><g fill="#dcaaff" filter="url(#nodeHalo)"><circle cx="88" cy="106" r="3"/><circle cx="110" cy="144" r="3"/><circle cx="130" cy="169" r="3.5"/><circle cx="113" cy="230" r="3"/><circle cx="169" cy="262" r="3"/><circle cx="224" cy="70" r="3"/><circle cx="227" cy="102" r="3"/><circle cx="455" cy="65" r="3"/><circle cx="472" cy="106" r="3"/><circle cx="450" cy="144" r="3"/><circle cx="430" cy="169" r="3.5"/><circle cx="447" cy="230" r="3"/><circle cx="391" cy="262" r="3"/><circle cx="336" cy="70" r="3"/><circle cx="333" cy="102" r="3"/></g><g fill="none" stroke="#52cfff" stroke-width="1" opacity=".34"><path d="M80 140 Q280 15 480 140"/><path d="M90 212 Q280 330 470 212"/><path d="M122 43 Q280 0 438 43"/><path d="M122 280 Q280 320 438 280"/></g></svg><div class="brain-caption"><span class="pulse-dot"></span> Neural activity map <span class="caption-divider">/</span> <span>Illustrative visualization</span></div></div></section>
<div class="cards" id="stats"></div><div class="section-heading"><h2>Explore your workspace</h2><span class="muted">Choose a tool to get started</span></div><div class="feature-grid"><article class="feature-card"><div class="feature-icon">◎</div><h3>Patient network</h3><p>Visualize profile relationships and adjust similarity thresholds by cohort.</p><button onclick="tab('network')">Explore network →</button></article><article class="feature-card"><div class="feature-icon">◈</div><h3>Cognitive analytics</h3><p>Compare profiles, review clustering, and inspect similarity explanations.</p><button onclick="tab('analytics')">Open analytics →</button></article><article class="feature-card"><div class="feature-icon">↗</div><h3>Longitudinal follow-ups</h3><p>Record visits and follow MMSE and MoCA score trends over time.</p><button onclick="tab('longitudinal')">View follow-ups →</button></article><article class="feature-card"><div class="feature-icon">♙</div><h3>Patient explorer</h3><p>Search profiles, filter cohorts, inspect details, and import or export CSV.</p><button onclick="tab('patients')">Browse profiles →</button></article><article class="feature-card"><div class="feature-icon">＋</div><h3>Assessments</h3><p>Record MoCA domain scores and review saved screening history.</p><button onclick="tab('mmse-moca')">Open assessments →</button></article><article class="feature-card"><div class="feature-icon">▤</div><h3>Research lab</h3><p>Review network statistics, evaluation metrics, and generate a research report.</p><button onclick="tab('research')">Open research lab →</button></article><section style="margin-top:22px"><div class="section-heading"><h2>Analysis workflow</h2><span class="muted">From structured profiles to interpretable patterns</span></div><div class="workflow-grid"><article class="workflow-step"><div class="workflow-number">01</div><h3>Build a profile</h3><p>Organize MMSE, MoCA, age and seven cognitive-domain measures into a consistent patient record.</p></article><article class="workflow-step"><div class="workflow-number">02</div><h3>Measure similarity</h3><p>Compare cognitive-domain vectors to identify profiles that are close under the selected distance method.</p></article><article class="workflow-step"><div class="workflow-number">03</div><h3>Explore the network</h3><p>Use thresholded connections and cohort filters to inspect relationships across the patient group.</p></article><article class="workflow-step"><div class="workflow-number">04</div><h3>Evaluate patterns</h3><p>Review clusters, graph statistics and follow-up score trends to support transparent project analysis.</p></article></div><div class="two"><section><h2>Methods in the workspace</h2><p class="muted">A practical toolkit spanning similarity, clustering and graph analysis.</p><div class="method-chips"><span class="method-chip">Weighted distance</span><span class="method-chip">Cosine similarity</span><span class="method-chip">Euclidean distance</span><span class="method-chip">K-means clustering</span><span class="method-chip">Silhouette evaluation</span><span class="method-chip">Graph density &amp; degree</span><span class="method-chip">MMSE / MoCA trends</span></div></section><section><h2>Designed for explainability</h2><p class="muted">Inspect which cognitive domains contribute most to a configured weighted comparison, review individual profiles, and export tabular data for further analysis.</p><div class="project-note">Similarity and clustering results are exploratory measures—not a diagnosis, prediction of disease, or replacement for professional clinical assessment.</div></section></div></section><div class="two" style="margin-top:22px"><section><h2>Cohort distribution</h2><p class="muted">Overview of profiles by cohort category.</p><div id="distribution"></div></section><section><h2>Quick actions</h2><p class="muted">Jump into a task or refresh the latest workspace data.</p><div class="toolbar"><button class="primary" onclick="tab('patients')">Add or explore patients</button><button onclick="load()">Refresh data</button><button onclick="location.href='/api/export-csv'">Export CSV</button></div><p id="mean" class="muted"></p></section></div></div></div><div id="network" class="hidden"><section><h2>Patient similarity network</h2><p class="muted">Each node is a patient; lines connect profiles with high cognitive similarity. Click a node to open its profile.</p><div class="toolbar"><label>Minimum similarity <input id="networkThreshold" type="number" min="0" max="100" value="85" style="width:90px"></label><label>Cohort <select id="networkDiagnosis"><option>All</option><option>Healthy</option><option>MCI</option><option>Alzheimer's</option></select></label><button onclick="drawNetwork()">Apply filters</button><button onclick="drawNetwork(true)">Reset filters</button><span class="muted">Green = Healthy · Blue = MCI · Gold = Alzheimer's</span></div><div id="networkSummary" class="muted"></div><div style="width:100%;overflow:auto"><svg id="networkGraph" viewBox="0 0 900 500" role="img" aria-label="Interactive patient similarity network" style="display:block;width:100%;min-width:600px;height:auto;border-radius:10px;background:#0d1525"></svg></div><div id="networkgrid" class="patientgrid" style="margin-top:12px"></div></section></div>
<div id="patients" class="hidden"><section><h2>Phase 1 · Register a patient</h2><p class="muted">Add an assessment profile with MMSE, MoCA and seven cognitive-domain scores.</p><form id="patientForm" onsubmit="addPatient(event)"><div class="toolbar"><input name="patient_code" required maxlength="40" placeholder="Patient code (e.g. P201)"><input name="age" type="number" min="18" max="120" required value="65" style="width:95px"><select name="sex"><option>Female</option><option>Male</option><option>Other</option><option>Unknown</option></select><select name="diagnosis"><option>Healthy</option><option selected>MCI</option><option>Alzheimer's</option></select><input name="mmse" type="number" min="0" max="30" step="0.1" required value="24" placeholder="MMSE" style="width:95px"><input name="moca" type="number" min="0" max="30" step="0.1" required value="20" placeholder="MoCA" style="width:95px"></div><div class="toolbar"><label>Memory <input name="memory" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Attention <input name="attention" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Executive <input name="executive" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Language <input name="language" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Visuospatial <input name="visuospatial" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Processing speed <input name="processing_speed" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label><label>Orientation <input name="orientation" type="number" min="0" max="100" step="0.1" required value="50" style="width:82px"></label></div><button class="primary" type="submit">Register patient</button> <span id="formStatus" class="muted" role="status"></span></form></section><section><h2>Patient explorer</h2><div class="toolbar"><input id="q" placeholder="Search patient code" oninput="renderPatients()"><select id="filter" onchange="renderPatients()"><option>All</option><option>Healthy</option><option>MCI</option><option>Alzheimer's</option></select><button onclick="location.href='/api/export-csv'">Export CSV</button><label class="btn">Import CSV<input type="file" accept=".csv" hidden onchange="importFile(this)"></label></div><div class="tablewrap"><table><thead><tr><th>Patient</th><th>Age</th><th>Diagnosis</th><th>MMSE</th><th>MoCA</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></section><div class="two"><section><h2>Selected profile</h2><div id="profile" class="muted">Choose Compare on a patient.</div></section><section><h2>Closest similar patients</h2><div id="similar" class="muted">Choose a patient to compare.</div></section></div></div>
<div id="analytics" class="hidden"><section class="brain-network-feature"><div class="brain-network-copy"><span class="brain-eyebrow">COGNITIVE ANALYSIS WORKSPACE</span><h2>Brain Network</h2><p>Explore connected cognitive regions through a glowing neural network visualization.</p><div class="brain-tags"><span><i></i> Neural connections</span><span><i></i> Cognitive patterns</span></div></div><div class="brain-visual" role="img" aria-label="Glowing blue and violet brain neural network illustration"><div class="brain-orbit orbit-one"></div><div class="brain-orbit orbit-two"></div><svg class="brain-svg" viewBox="0 0 560 360" aria-hidden="true"><defs><radialGradient id="brainCore"><stop offset="0" stop-color="#2ce8ff" stop-opacity=".38"/><stop offset=".65" stop-color="#1678ff" stop-opacity=".14"/><stop offset="1" stop-color="#06142d" stop-opacity="0"/></radialGradient><linearGradient id="cortex" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#37efff"/><stop offset=".42" stop-color="#248cff"/><stop offset=".72" stop-color="#6367ff"/><stop offset="1" stop-color="#e27cff"/></linearGradient><filter id="cortexGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="4" result="blur"/><feColorMatrix in="blur" type="matrix" values="0 0 0 0 .05 0 0 0 0 .48 0 0 0 0 1 0 0 0 .9 0" result="blueblur"/><feMerge><feMergeNode in="blueblur"/><feMergeNode in="SourceGraphic"/></feMerge></filter><filter id="nodeHalo"><feGaussianBlur stdDeviation="2.6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><ellipse cx="280" cy="178" rx="250" ry="165" fill="url(#brainCore)"/><g fill="none" stroke="url(#cortex)" stroke-linecap="round" stroke-linejoin="round" filter="url(#cortexGlow)"><path stroke-width="3.2" d="M278 67 C263 42 229 28 199 39 C179 21 147 36 138 57 C106 54 82 79 88 106 C60 126 69 158 88 174 C71 198 90 224 113 230 C114 258 145 275 169 262 C191 285 219 274 237 258 C253 268 269 251 278 235"/><path stroke-width="3.2" d="M282 67 C297 42 331 28 361 39 C381 21 413 36 422 57 C454 54 478 79 472 106 C500 126 491 158 472 174 C489 198 470 224 447 230 C446 258 415 275 391 262 C369 285 341 274 323 258 C307 268 291 251 282 235"/><path stroke-width="2.3" d="M278 68 C253 60 236 75 240 94 C216 102 215 124 231 137 C208 152 218 177 238 184 C224 203 239 222 258 220 L278 235 M282 68 C307 60 324 75 320 94 C344 102 345 124 329 137 C352 152 342 177 322 184 C336 203 321 222 302 220 L282 235"/><path stroke-width="2" d="M139 58 C157 64 166 78 157 94 C141 109 151 124 172 125 C185 139 176 155 159 162 C144 176 154 194 174 197 C186 211 176 229 165 239 M199 40 C194 58 208 70 224 70 C241 77 240 91 227 102 M91 107 C111 112 120 128 110 144 C103 157 113 169 130 169 M113 230 C130 221 143 225 150 240 M169 262 C177 246 197 243 210 255 M421 58 C403 64 394 78 403 94 C419 109 409 124 388 125 C375 139 384 155 401 162 C416 176 406 194 386 197 C374 211 384 229 395 239 M361 40 C366 58 352 70 336 70 C319 77 320 91 333 102 M469 107 C449 112 440 128 450 144 C457 157 447 169 430 169 M447 230 C430 221 417 225 410 240 M391 262 C383 246 363 243 350 255"/><path stroke-width="1.5" opacity=".85" d="M278 67 L282 235 M157 94 L190 105 L227 102 L240 94 M172 125 L204 137 L231 137 M159 162 L197 173 L238 184 M174 197 L208 207 L258 220 M165 239 L198 229 L237 258 M403 94 L370 105 L333 102 M388 125 L356 137 L329 137 M401 162 L363 173 L322 184 M386 197 L352 207 L302 220 M395 239 L362 229 L323 258"/></g><g fill="none" stroke="#54dfff" stroke-width="1.15" opacity=".7"><path d="M68 88 L88 106 L110 144 L130 169 L113 230 L150 240 L169 262 L210 255 L237 258 L278 235"/><path d="M492 88 L472 106 L450 144 L430 169 L447 230 L410 240 L391 262 L350 255 L323 258 L282 235"/><path d="M105 65 L138 57 L157 94 L190 105 L204 137 L197 173 L208 207 L198 229 L210 255"/><path d="M455 65 L422 57 L403 94 L370 105 L356 137 L363 173 L352 207 L362 229 L350 255"/><path d="M199 40 L224 70 L227 102 L204 137 L197 173 M361 40 L336 70 L333 102 L356 137 L363 173"/></g><g fill="#b8f7ff" filter="url(#nodeHalo)"><circle cx="138" cy="57" r="4"/><circle cx="157" cy="94" r="4"/><circle cx="190" cy="105" r="4.5"/><circle cx="172" cy="125" r="4"/><circle cx="204" cy="137" r="5"/><circle cx="159" cy="162" r="4"/><circle cx="197" cy="173" r="4.5"/><circle cx="174" cy="197" r="4"/><circle cx="208" cy="207" r="4"/><circle cx="165" cy="239" r="4"/><circle cx="198" cy="229" r="4"/><circle cx="210" cy="255" r="4"/><circle cx="240" cy="94" r="5"/><circle cx="231" cy="137" r="4.5"/><circle cx="238" cy="184" r="5"/><circle cx="258" cy="220" r="4"/><circle cx="278" cy="67" r="5"/><circle cx="278" cy="235" r="5"/><circle cx="422" cy="57" r="4"/><circle cx="403" cy="94" r="4"/><circle cx="370" cy="105" r="4.5"/><circle cx="388" cy="125" r="4"/><circle cx="356" cy="137" r="5"/><circle cx="401" cy="162" r="4"/><circle cx="363" cy="173" r="4.5"/><circle cx="386" cy="197" r="4"/><circle cx="352" cy="207" r="4"/><circle cx="395" cy="239" r="4"/><circle cx="362" cy="229" r="4"/><circle cx="350" cy="255" r="4"/><circle cx="320" cy="94" r="5"/><circle cx="329" cy="137" r="4.5"/><circle cx="322" cy="184" r="5"/><circle cx="302" cy="220" r="4"/></g><g fill="#dcaaff" filter="url(#nodeHalo)"><circle cx="88" cy="106" r="3"/><circle cx="110" cy="144" r="3"/><circle cx="130" cy="169" r="3.5"/><circle cx="113" cy="230" r="3"/><circle cx="169" cy="262" r="3"/><circle cx="224" cy="70" r="3"/><circle cx="227" cy="102" r="3"/><circle cx="455" cy="65" r="3"/><circle cx="472" cy="106" r="3"/><circle cx="450" cy="144" r="3"/><circle cx="430" cy="169" r="3.5"/><circle cx="447" cy="230" r="3"/><circle cx="391" cy="262" r="3"/><circle cx="336" cy="70" r="3"/><circle cx="333" cy="102" r="3"/></g><g fill="none" stroke="#52cfff" stroke-width="1" opacity=".34"><path d="M80 140 Q280 15 480 140"/><path d="M90 212 Q280 330 470 212"/><path d="M122 43 Q280 0 438 43"/><path d="M122 280 Q280 320 438 280"/></g></svg><div class="brain-caption"><span class="pulse-dot"></span> Neural activity map <span class="caption-divider">/</span> <span>Illustrative visualization</span></div></div></section><section><h2>Phase 2 · Similarity analysis</h2><p class="muted">Compare cognitive profiles using multiple methods and adjust the minimum score.</p><div class="toolbar"><label>Patient <select id="analysisPatient"></select></label><label>Method <select id="simMethod"><option value="weighted">Weighted distance</option><option value="cosine">Cosine similarity</option><option value="euclidean">Euclidean similarity</option></select></label><label>Minimum score <input id="simThreshold" type="number" min="0" max="100" value="75" style="width:90px"></label><button class="primary" onclick="runSimilarity()">Compare profiles</button></div><div id="similarityResults" class="muted">Choose settings and run a comparison.</div><section><h2>Explainable similarity</h2><p class="muted">Select “Why similar?” beside a result to inspect weighted domain differences.</p><div id="explanationResults" class="muted">No pair selected yet.</div></section></section><div class="two"><section><h2>K-means clustering</h2><div class="toolbar"><label>Clusters <select id="clusterCount"><option>2</option><option selected>3</option><option>4</option><option>5</option></select></label><button onclick="runClusters()">Run clustering</button></div><div id="clusterResults" class="muted"></div></section><section><h2>Evaluation metrics</h2><button onclick="runPhase2()">Calculate metrics</button><div id="evaluationResults" class="muted" style="margin-top:10px"></div></section></div><section><h2>Domain feature contribution</h2><div id="featureImportance" class="muted">Run evaluation to view weighted contributions.</div></section><section><h2>Graph statistics</h2><div class="toolbar"><label>Edge threshold <input id="graphThreshold" type="number" min="0" max="100" value="85" style="width:90px"></label><button onclick="runGraphFeatures()">Calculate graph features</button></div><div id="graphResults" class="muted"></div></section></div>
<div id="longitudinal" class="hidden"><section><h2>Phase 3 · Longitudinal cognitive visits</h2><p class="muted">Record follow-up assessments and review changes over time.</p><form id="visitForm" onsubmit="addVisit(event)"><div class="toolbar"><label>Patient <select id="visitPatient" name="patient_id" required onchange="loadVisits()"></select></label><label>Visit date <input name="visit_date" type="date" required></label><label>MMSE <input name="mmse" type="number" min="0" max="30" step="0.1" value="24" required style="width:85px"></label><label>MoCA <input name="moca" type="number" min="0" max="30" step="0.1" value="20" required style="width:85px"></label></div><div class="toolbar"><label>Memory <input name="memory" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Attention <input name="attention" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Executive <input name="executive" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Language <input name="language" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Visuospatial <input name="visuospatial" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Processing speed <input name="processing_speed" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label><label>Orientation <input name="orientation" type="number" min="0" max="100" step="0.1" value="50" required style="width:82px"></label></div><button class="primary" type="submit">Save follow-up visit</button> <span id="visitStatus" class="muted" role="status"></span></form></section><section><h2>Visit history and progression</h2><div id="visitHistory" class="muted">Select a patient to load visit history.</div><div id="progression" style="margin-top:12px"></div><div class="toolbar"><a href="/api/report" target="_blank" style="color:var(--blue)">Open printable report / Save as PDF</a> · <a href="/api/export-csv" style="color:var(--blue)">Download patient CSV</a></div></section><section><h2>Cognitive-domain network</h2><p class="muted">Explore the patient similarity network and graph statistics.</p><button onclick="tab('network')">Open patient network</button></section></div>
<div id="mmse-moca" class="hidden"><section><h2>Alzheimer’s Cognitive MoCA Assessment</h2><p class="muted">For recording an assessment administered by a qualified assessor using authorized MoCA materials. The test prompts are intentionally not reproduced here.</p><form id="screeningForm" onsubmit="saveScreening(event)"><div class="toolbar"><label>Patient <select id="screeningPatient" name="patient_id" required onchange="loadScreeningHistory()"></select></label><label>Assessment date <input name="visit_date" type="date" required></label><label>MMSE total / 30 (if available) <input name="mmse" type="number" min="0" max="30" step="0.1" value="24" required style="width:130px"></label><label>Years of education <input id="mocaEducation" type="number" min="0" max="40" step="1" value="12" required style="width:90px"></label></div><h3>MoCA domain scores</h3><p class="muted">Enter the score achieved for each section of the official assessment. The total updates automatically; the education adjustment is applied when education is 12 years or less, up to a maximum total of 30.</p><div class="toolbar"><label>Visuospatial / Executive (0–5) <input id="mocaVE" type="number" min="0" max="5" step="1" value="3" required style="width:80px"></label><label>Naming (0–3) <input id="mocaNaming" type="number" min="0" max="3" step="1" value="3" required style="width:80px"></label><label>Attention (0–6) <input id="mocaAttention" type="number" min="0" max="6" step="1" value="4" required style="width:80px"></label><label>Language (0–3) <input id="mocaLanguage" type="number" min="0" max="3" step="1" value="2" required style="width:80px"></label><label>Abstraction (0–2) <input id="mocaAbstraction" type="number" min="0" max="2" step="1" value="1" required style="width:80px"></label><label>Delayed recall (0–5) <input id="mocaRecall" type="number" min="0" max="5" step="1" value="2" required style="width:80px"></label><label>Orientation (0–6) <input id="mocaOrientation" type="number" min="0" max="6" step="1" value="5" required style="width:80px"></label></div><div class="cards"><div class="card"><span class="muted">Adjusted MoCA total</span><strong id="mocaCalculated" style="font-size:1.8rem">21 / 30</strong></div><div class="card"><span class="muted">Scoring note</span><strong id="mocaAdjustmentNote">Education adjustment applied if eligible</strong></div></div><input name="moca" id="mocaTotal" type="hidden" value="21"><h3>Additional research profile</h3><p class="muted">MoCA does not provide a dedicated processing-speed score. Enter a separately assessed 0–100 research score if available; the other profile fields are normalized from the domain scores above.</p><div class="toolbar"><label>Processing speed (separate measure, 0–100) <input id="mocaProcessingSpeed" name="processing_speed" type="number" min="0" max="100" step="0.1" value="50" required style="width:100px"></label></div><input name="memory" id="mocaMemoryProfile" type="hidden" value="40"><input name="attention" id="mocaAttentionProfile" type="hidden" value="66.7"><input name="executive" id="mocaExecutiveProfile" type="hidden" value="60"><input name="language" id="mocaLanguageProfile" type="hidden" value="66.7"><input name="visuospatial" id="mocaVisuospatialProfile" type="hidden" value="60"><input name="orientation" id="mocaOrientationProfile" type="hidden" value="83.3"><button class="primary" type="submit">Save MoCA assessment</button> <span id="screeningStatus" class="muted" role="status"></span></form></section><section><h2>MoCA screening history</h2><div id="screeningHistory" class="muted">Choose a patient to review previous scores.</div></section><div class="notice">MoCA is a cognitive screening tool, not a diagnosis of Alzheimer’s disease. Interpret results in clinical context and follow the official scoring guidance. Use only authorized assessment materials; do not enter identifiable real patient data into this demo.</div></div><div id="research" class="hidden"><div class="cards" id="researchcards"></div><section><h2>Research summary</h2><p class="muted">Exploratory metrics on synthetic demo records; not clinical evidence.</p><div id="researchtext"></div><button onclick="load()">Refresh summary</button> <button onclick="runPhase2()">Run evaluation</button><div id="researchSummary" style="margin-top:12px"></div><div class="toolbar"><a href="/api/export-csv" style="color:var(--blue)">Download patient data (CSV)</a><a href="/api/report" target="_blank" style="color:var(--blue)">Open research report (Print / Save PDF)</a></div></section></div><footer class="site-footer"><div><div class="footer-brand">✳ Patient Similarity Network</div><div>Connected profiles. Clearer cognitive insights.</div></div><div class="footer-note">Built for cognitive profile analysis and academic project evaluation.</div></footer></main><nav class="bottom-nav" aria-label="Quick navigation"><button class="active" data-tab="overview"><span>⌂</span>Home</button><button data-tab="network"><span>◎</span>Network</button><button data-tab="patients"><span>♙</span>Patients</button><button data-tab="analytics"><span>◈</span>Analytics</button><button data-tab="longitudinal"><span>↗</span>Visits</button></nav><script>
let patients=[],stats={},currentUser=null,authModeValue='login';const domains=['memory','attention','executive','language','visuospatial','processing_speed','orientation'];const colors={Healthy:'var(--mint)',MCI:'var(--blue)',"Alzheimer's":'var(--gold)'};
function tab(n){
 const allowed=['overview','network','patients','analytics','longitudinal','research','mmse-moca','admin'];
 if(!allowed.includes(n))return;
 if(n==='admin'&&currentUser?.role!=='admin')return;
 // Set both class and inline display so navigation remains reliable across mobile/desktop browsers.
 allowed.forEach(id=>{
   const panel=document.getElementById(id);
   if(!panel)return;
   const active=id===n;
   panel.classList.toggle('hidden',!active);
   panel.style.display=active?'block':'none';
   panel.setAttribute('aria-hidden',active?'false':'true');
 });
 document.querySelectorAll('[data-tab]').forEach(b=>{
   const active=b.dataset.tab===n;
   b.classList.toggle('active',active);
   if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');
 });
 const error=document.getElementById('error');
 if(error){error.classList.add('hidden');error.textContent=''}
 if(n==='longitudinal')loadVisits();
 if(n==='mmse-moca')loadScreeningHistory();
 if(n==='analytics')runPhase2();
 if(n==='network')drawNetwork();
 if(n==='admin')loadAdminUsers();
}
document.querySelectorAll('[data-tab]').forEach(b=>{
 b.addEventListener('click',()=>tab(b.dataset.tab));
});
async function get(u){let r=await fetch(u);if(!r.ok)throw Error((await r.text()).slice(0,150));return r.json()}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){try{document.getElementById('error').classList.add('hidden');[patients,stats]=await Promise.all([get('/api/patients'),get('/api/stats')]);render();refreshPatientSelects()}catch(e){let x=document.getElementById('error');x.textContent='Could not load data: '+e.message;x.classList.remove('hidden')}}
function render(){document.getElementById('heroTotal').textContent=stats.total??'—';document.getElementById('stats').innerHTML=[['Total patients',stats.total],['Healthy cohort',stats.healthy],['MCI cohort',stats.mci],["Alzheimer’s cohort",stats.alzheimers]].map(([a,b],i)=>'<div class="card"><div class="card-icon">'+['♙','◉','◈','✳'][i]+'</div><small>'+a+'</small><strong>'+(b??'—')+'</strong><small>Profiles in workspace</small></div>').join('');let total=stats.total||1;document.getElementById('distribution').innerHTML=[['Healthy',stats.healthy],['MCI',stats.mci],["Alzheimer's",stats.alzheimers]].map(([n,v])=>'<div class="metric"><span>'+n+'</span><b>'+v+'</b></div><div class="bar"><span style="width:'+(v/total*100)+'%;background:'+colors[n]+'"></span></div>').join('');document.getElementById('mean').textContent='Mean MMSE: '+stats.mean_mmse+' / 30';document.getElementById('networkgrid').innerHTML=patients.slice(0,30).map(p=>'<button class="patient" onclick="selectPatient('+p.id+')"><b>'+esc(p.patient_code)+'</b><span style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</span><small>Age '+p.age+' · MMSE '+p.mmse+'</small></button>').join('');renderPatients();document.getElementById('researchcards').innerHTML=[['Records',stats.total],['Cohorts',3],['Similarity','Weighted'],['Clinical status','Not validated']].map(([a,b])=>'<div class="card"><small>'+a+'</small><strong style="font-size:21px">'+b+'</strong></div>').join('');document.getElementById('researchtext').textContent='Similarity compares seven cognitive domains. Clustering and evaluation metrics are exploratory and should be interpreted alongside the project methodology.'}

function refreshPatientSelects(){['analysisPatient','visitPatient','screeningPatient'].forEach(id=>{const el=document.getElementById(id);if(!el)return;const prev=el.value;el.innerHTML=patients.map(p=>'<option value="'+p.id+'">'+esc(p.patient_code)+' · '+esc(p.diagnosis)+'</option>').join('');if(patients.some(p=>String(p.id)===prev))el.value=prev});}
async function runSimilarity(){const id=document.getElementById('analysisPatient').value;if(!id)return;const method=document.getElementById('simMethod').value;const threshold=Math.max(0,Math.min(100,Number(document.getElementById('simThreshold').value)||0));const out=document.getElementById('similarityResults');out.textContent='Calculating...';try{const rows=await get('/api/patients/'+id+'/similar?method='+encodeURIComponent(method)+'&threshold='+threshold);out.innerHTML=rows.length?'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Diagnosis</th><th>Similarity</th><th>Explain</th></tr></thead><tbody>'+rows.map(p=>'<tr><td>'+esc(p.patient_code)+'</td><td>'+esc(p.diagnosis)+'</td><td>'+p.similarity+'%</td><td><button onclick="showExplanation('+id+','+p.id+')">Why similar?</button></td></tr>').join('')+'</tbody></table></div>':'No matches above '+threshold+'%';}catch(e){out.textContent=e.message}}
async function showExplanation(id,compareTo){const out=document.getElementById("explanationResults");out.textContent="Explaining comparison…";try{const d=await get("/api/patients/"+id+"/explanation?compare_to="+compareTo);out.innerHTML="<div class=\\\"metric\\\"><span>Comparison</span><b>"+esc(d.patient_code)+" ↔ "+esc(d.comparison_code)+"</b></div><div class=\\\"metric\\\"><span>Similarity</span><b>"+d.similarity+"%</b></div><div class=\\\"tablewrap\\\"><table><thead><tr><th>Domain</th><th>Selected</th><th>Compared</th><th>Gap</th><th>Weight</th><th>Contribution</th></tr></thead><tbody>"+d.domains.map(x=>"<tr><td>"+esc(x.domain.replace("_"," "))+"</td><td>"+x.patient_value+"</td><td>"+x.comparison_value+"</td><td>"+x.absolute_gap+"</td><td>"+x.weight_percent+"%</td><td>"+x.distance_contribution+"</td></tr>").join("")+"</tbody></table></div><p class=\\\"muted\\\">"+esc(d.explanation)+" "+esc(d.note)+"</p>"}catch(e){out.textContent=e.message}}
async function runClusters(){const out=document.getElementById('clusterResults');out.textContent='Clustering...';try{const d=await get('/api/clusters?k='+document.getElementById('clusterCount').value);out.innerHTML='<p>'+d.note+'</p><div class="metric"><span>Records grouped</span><b>'+d.clusters.length+'</b></div>'+Object.entries(d.sizes).map(([k,v])=>'<div class="metric"><span>Cluster '+(Number(k)+1)+'</span><b>'+v+' patients</b></div>').join('')+'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Cluster</th></tr></thead><tbody>'+d.clusters.map(x=>'<tr><td>'+esc(x.patient_code)+'</td><td>'+(x.cluster+1)+'</td></tr>').join('')+'</tbody></table></div>';}catch(e){out.textContent=e.message}}
async function runPhase2(){try{const [ev,fi]=await Promise.all([get('/api/evaluation'),get('/api/feature-importance')]);document.getElementById('evaluationResults').innerHTML='<div class="metric"><span>Records evaluated</span><b>'+ev.patients+'</b></div><div class="metric"><span>Silhouette score</span><b>'+(ev.silhouette===null?'Not available':ev.silhouette)+'</b></div><p class="muted">'+esc(ev.note)+' '+esc(ev.ari_note||'')+'</p>';document.getElementById('featureImportance').innerHTML=fi.features.map(x=>'<div class="metric"><span>'+esc(x.feature.replace('_',' '))+'</span><b>'+x.percent+'%</b></div><div class="bar"><span style="width:'+x.percent+'%"></span></div>').join('')+'<small>'+esc(fi.method)+'</small>';document.getElementById('researchSummary').textContent='Silhouette: '+(ev.silhouette===null?'not available':ev.silhouette)+' · records: '+ev.patients;await runClusters();await runGraphFeatures()}catch(e){document.getElementById('evaluationResults').textContent='Evaluation error: '+e.message}}
async function runGraphFeatures(){const out=document.getElementById('graphResults');try{const threshold=Math.max(0,Math.min(100,Number(document.getElementById('graphThreshold').value)||85));const d=await get('/api/graph-features?threshold='+threshold);out.innerHTML='<div class="metric"><span>Nodes</span><b>'+d.nodes+'</b></div><div class="metric"><span>Edges</span><b>'+d.edges+'</b></div><div class="metric"><span>Network density</span><b>'+d.density+'</b></div><div class="metric"><span>Average degree</span><b>'+d.average_degree+'</b></div><h3>Most connected patients</h3>'+d.top_degree.map(p=>'<div class="metric"><span>'+esc(p.patient_code)+'</span><b>'+p.degree+' connections</b></div>').join('')+'<small>'+esc(d.note)+'</small>'}catch(e){out.textContent=e.message}}
async function loadVisits(){const id=document.getElementById('visitPatient')?.value;if(!id)return;const out=document.getElementById('visitHistory');try{const d=await get('/api/patients/'+id+'/visits');const v=d.visits||[];out.innerHTML='<div class="metric"><span>Patient</span><b>'+esc(d.patient_code)+'</b></div><div class="tablewrap"><table><thead><tr><th>Date</th><th>MMSE</th><th>MoCA</th><th>Mean domain score</th></tr></thead><tbody>'+v.map(x=>'<tr><td>'+esc(x.visit_date)+'</td><td>'+x.mmse+'</td><td>'+x.moca+'</td><td>'+Math.round(domains.reduce((a,k)=>a+Number(x[k]),0)/domains.length*10)/10+'</td></tr>').join('')+'</tbody></table></div>';document.getElementById('progression').innerHTML='<h3>Longitudinal score trends</h3><p class="muted">MMSE and MoCA across recorded visits (scores out of 30).</p>'+renderTrendChart(v)}catch(e){out.textContent=e.message}}
async function addVisit(e){e.preventDefault();const form=e.currentTarget;const status=document.getElementById('visitStatus');const data=Object.fromEntries(new FormData(form).entries());const id=data.patient_id;delete data.patient_id;['mmse','moca',...domains].forEach(k=>data[k]=Number(data[k]));status.textContent='Saving...';try{const r=await fetch('/api/patients/'+id+'/visits',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await r.json();if(!r.ok)throw Error(result.detail||'Could not save visit');status.textContent='Follow-up saved';await load();await loadVisits()}catch(err){status.textContent=err.message}}
async function loadScreeningHistory(){const id=document.getElementById('screeningPatient')?.value;const out=document.getElementById('screeningHistory');if(!id||!out)return;try{const d=await get('/api/patients/'+id+'/visits');const visits=d.visits||[];out.innerHTML=visits.length?'<div class="tablewrap"><table><thead><tr><th>Date</th><th>MMSE / 30</th><th>MoCA / 30</th><th>Domain profile mean</th></tr></thead><tbody>'+visits.map(v=>'<tr><td>'+esc(v.visit_date)+'</td><td>'+Number(v.mmse).toFixed(1)+'</td><td>'+Number(v.moca).toFixed(1)+'</td><td>'+(domains.reduce((a,k)=>a+Number(v[k]),0)/domains.length).toFixed(1)+'</td></tr>').join('')+'</tbody></table></div>':'No screening records yet.'}catch(e){out.textContent='Could not load screening history: '+e.message}}
function renderTrendChart(visits){if(!visits.length)return 'No visits recorded.';const W=760,H=250,L=42,R=18,T=18,B=42,iw=W-L-R,ih=H-T-B;const x=i=>L+(visits.length===1?iw/2:i*iw/(visits.length-1));const y=v=>T+ih-(Math.max(0,Math.min(30,Number(v)||0))/30)*ih;const grid=[0,10,20,30].map(n=>'<line x1="'+L+'" y1="'+y(n)+'" x2="'+(W-R)+'" y2="'+y(n)+'" stroke="#263650"/><text x="'+(L-8)+'" y="'+(y(n)+4)+'" text-anchor="end" fill="#9eabc2" font-size="11">'+n+'</text>').join('');const series=(key,color)=>'<polyline points="'+visits.map((v,i)=>x(i)+','+y(v[key])).join(' ')+'" fill="none" stroke="'+color+'" stroke-width="3"/>'+visits.map((v,i)=>'<circle cx="'+x(i)+'" cy="'+y(v[key])+'" r="4" fill="'+color+'"><title>'+esc(v.visit_date)+' · '+key.toUpperCase()+' '+v[key]+'/30</title></circle>').join('');return '<div style="overflow-x:auto"><svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="MMSE and MoCA trend chart" style="width:100%;min-width:520px">'+grid+series('mmse','#7dd3b0')+series('moca','#8ea9ff')+visits.map((v,i)=>'<text x="'+x(i)+'" y="'+(H-15)+'" text-anchor="middle" fill="#9eabc2" font-size="10">'+esc(v.visit_date)+'</text>').join('')+'</svg></div><p><span style="color:#7dd3b0">● MMSE</span> &nbsp; <span style="color:#8ea9ff">● MoCA</span></p>'}
function updateMoCATotal(){const ids=['mocaVE','mocaNaming','mocaAttention','mocaLanguage','mocaAbstraction','mocaRecall','mocaOrientation'];const max=[5,3,6,3,2,5,6];const vals=ids.map(id=>Number(document.getElementById(id).value));const raw=vals.reduce((a,b)=>a+b,0);const edu=Number(document.getElementById('mocaEducation').value);const adjusted=Math.min(30,raw+(edu<=12?1:0));document.getElementById('mocaTotal').value=adjusted;document.getElementById('mocaCalculated').textContent=adjusted+' / 30';document.getElementById('mocaAdjustmentNote').textContent=edu<=12?'Education adjustment: +1 point (if eligible)':'No education adjustment';const pct=vals.map((v,i)=>100*v/max[i]);document.getElementById('mocaVisuospatialProfile').value=(pct[0]).toFixed(1);document.getElementById('mocaExecutiveProfile').value=(pct[0]).toFixed(1);document.getElementById('mocaAttentionProfile').value=(pct[2]).toFixed(1);document.getElementById('mocaLanguageProfile').value=(100*(vals[1]+vals[3])/(max[1]+max[3])).toFixed(1);document.getElementById('mocaMemoryProfile').value=(pct[5]).toFixed(1);document.getElementById('mocaOrientationProfile').value=(pct[6]).toFixed(1)}
['mocaVE','mocaNaming','mocaAttention','mocaLanguage','mocaAbstraction','mocaRecall','mocaOrientation','mocaEducation'].forEach(id=>document.getElementById(id).addEventListener('input',updateMoCATotal));
async function saveScreening(e){e.preventDefault();updateMoCATotal();const form=e.currentTarget;const status=document.getElementById('screeningStatus');const data=Object.fromEntries(new FormData(form).entries());const id=data.patient_id;delete data.patient_id;['mmse','moca',...domains].forEach(k=>data[k]=Number(data[k]));status.textContent='Saving...';try{const r=await fetch('/api/patients/'+id+'/visits',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await r.json();if(!r.ok)throw Error(result.detail||'Could not save MoCA assessment');status.textContent='MoCA assessment saved.';await load();await loadScreeningHistory()}catch(err){status.textContent=err.message}}
updateMoCATotal();
function renderPatients(){let q=(document.getElementById('q')?.value||'').toLowerCase(),f=document.getElementById('filter')?.value||'All';let list=patients.filter(p=>p.patient_code.toLowerCase().includes(q)&&(f==='All'||p.diagnosis===f));document.getElementById('rows').innerHTML=list.map(p=>'<tr><td>'+esc(p.patient_code)+'</td><td>'+p.age+'</td><td style="color:'+colors[p.diagnosis]+'">'+esc(p.diagnosis)+'</td><td>'+p.mmse+'</td><td>'+p.moca+'</td><td><button onclick="selectPatient('+p.id+')">Compare</button></td></tr>').join('')}
async function addPatient(e){e.preventDefault();const form=e.currentTarget;const status=document.getElementById('formStatus');const data=Object.fromEntries(new FormData(form).entries());['age','mmse','moca',...domains].forEach(k=>data[k]=Number(data[k]));status.textContent='Saving...';try{let r=await fetch('/api/patients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let result=await r.json();if(!r.ok)throw Error(result.detail||'Could not register patient');status.textContent='Registered '+result.patient_code;form.reset();await load();await selectPatient(result.id)}catch(err){status.textContent=err.message}}

async function drawNetwork(){const svg=document.getElementById('networkGraph');if(!svg)return;try{if(arguments.length&&arguments[0]){document.getElementById("networkThreshold").value=85;document.getElementById("networkDiagnosis").value="All"}const threshold=Math.max(0,Math.min(100,Number(document.getElementById("networkThreshold")?.value)||85));const diagnosis=document.getElementById("networkDiagnosis")?.value||"All";const data=await get("/api/network?threshold="+threshold+"&diagnosis="+encodeURIComponent(diagnosis));const nodes=data.nodes.slice(0,45);const map=new Map(nodes.map((n,i)=>{const a=2*Math.PI*i/nodes.length-Math.PI/2;return[n.id,{...n,x:450+195*Math.cos(a),y:250+195*Math.sin(a)}]}));const edges=data.edges.filter(e=>map.has(e.source)&&map.has(e.target));const lines=edges.map(e=>{const a=map.get(e.source),b=map.get(e.target);return '<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="#607aa4" stroke-opacity=".45" stroke-width="'+(1+(e.weight-85)/8)+'"><title>Similarity '+e.weight+'%</title></line>'}).join('');const circles=nodes.map(n=>{const p=map.get(n.id),c=colors[n.diagnosis]||'#8ea9ff';return '<g onclick="selectPatient('+n.id+')" style="cursor:pointer"><circle cx="'+p.x+'" cy="'+p.y+'" r="10" fill="'+c+'" stroke="#eef4ff" stroke-width="1.5"><title>'+esc(n.label)+' · '+esc(n.diagnosis)+'</title></circle><text x="'+p.x+'" y="'+(p.y+24)+'" text-anchor="middle" fill="#dce6f7" font-size="10">'+esc(n.label)+'</text></g>'}).join('');svg.innerHTML='<rect width="900" height="500" fill="#0d1525" rx="10"/>'+lines+circles;const summary=document.getElementById("networkSummary");if(summary)summary.textContent="Showing "+nodes.length+" nodes and "+edges.length+" connections at ≥"+threshold+"% similarity · cohort: "+diagnosis+". Click a node to inspect its profile."}catch(e){svg.innerHTML='<text x="20" y="35" fill="#f3c47a">Network could not load: '+esc(e.message)+'</text>'}}
async function selectPatient(id){let p=patients.find(x=>x.id===id);if(!p)return;tab('patients');document.getElementById('profile').innerHTML='<h3>'+esc(p.patient_code)+' · '+p.age+' years</h3><p>'+esc(p.sex)+' · '+esc(p.diagnosis)+'</p>'+domains.map(d=>'<div class="metric"><span>'+d.replace('_',' ')+'</span><b>'+p[d]+'</b></div><div class="bar"><span style="width:'+p[d]+'%"></span></div>').join('');try{let sim=await get('/api/patients/'+id+'/similar');document.getElementById('similar').innerHTML=sim.map(x=>'<div class="metric"><span>'+esc(x.patient_code)+' · '+esc(x.diagnosis)+'</span><b>'+x.similarity+'%</b></div>').join('')||'No other patients yet'}catch(e){document.getElementById('similar').textContent=e.message}}
async function importFile(input){let f=input.files[0];if(!f)return;let d=new FormData();d.append('file',f);try{let r=await fetch('/api/import-csv',{method:'POST',body:d});if(!r.ok)throw Error(await r.text());let x=await r.json();await load();alert('Imported '+x.added+' records')}catch(e){alert('CSV import failed: '+e.message)}input.value=''}

function authMode(mode){authModeValue=mode;document.getElementById('nameWrap').classList.toggle('hidden',mode!=='register');document.querySelector('#authForm [name=name]').required=mode==='register';document.getElementById('authSubmit').textContent=mode==='register'?'Create account':'Sign in';document.getElementById('loginMode').classList.toggle('primary',mode==='login');document.getElementById('registerMode').classList.toggle('primary',mode==='register');document.getElementById('authMessage').textContent='';document.querySelector('#authForm [name=password]').autocomplete=mode==='register'?'new-password':'current-password';}
function isAdminRoute(){return location.pathname==='/admin'||location.pathname.startsWith('/admin/')}
function setupAuthRoute(){if(isAdminRoute()){document.title='PSN Admin Console';document.getElementById('authTitle').textContent='Administrator sign in';document.getElementById('authSubtitle').textContent='Sign in with your PSN administrator account to manage users and access roles.';document.getElementById('registerMode').classList.add('hidden');document.getElementById('adminBackLink').classList.remove('hidden');authMode('login')}}
async function checkAuth(){try{const d=await get('/api/auth/me');if(d.user){currentUser=d.user;if(isAdminRoute()&&currentUser.role!=='admin'){document.getElementById('authScreen').style.display='flex';document.getElementById('appShell').style.display='none';document.getElementById('authMessage').textContent='This account does not have administrator access.';return}showApp()}else{document.getElementById('authScreen').style.display='flex';document.getElementById('appShell').style.display='none'}}catch(e){document.getElementById('authMessage').textContent=e.message}}
function showApp(){document.getElementById('authScreen').style.display='none';document.getElementById('appShell').style.display='block';document.getElementById('signedInAs').textContent=currentUser.name+' · '+(currentUser.role==='admin'?'Administrator':'Study Analyst');const isAdmin=currentUser.role==='admin';document.getElementById('adminButton').classList.toggle('hidden',!isAdmin);document.getElementById('adminNav').classList.toggle('hidden',!isAdmin);if(isAdminRoute()&&isAdmin){tab('admin')}else{tab('overview')}load();drawNetwork()}
async function submitAuth(e){e.preventDefault();const form=e.currentTarget;const data=Object.fromEntries(new FormData(form).entries());const msg=document.getElementById('authMessage');msg.textContent='Please wait…';try{const r=await fetch('/api/auth/'+(authModeValue==='register'?'register':'login'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const d=await r.json();if(!r.ok)throw Error(d.detail||'Authentication failed');currentUser=d.user;if(isAdminRoute()&&currentUser.role!=='admin'){await fetch('/api/auth/logout',{method:'POST'});currentUser=null;throw Error('This account does not have administrator access. Sign in with your admin account.')}showApp()}catch(err){msg.textContent=err.message}}
async function logout(){await fetch('/api/auth/logout',{method:'POST'});currentUser=null;document.getElementById('appShell').style.display='none';document.getElementById('authScreen').style.display='flex';authMode('login')}
async function loadAdminUsers(){if(currentUser?.role!=='admin')return;const out=document.getElementById('adminUsers');out.textContent='Loading accounts…';try{const users=await get('/api/admin/users');const admins=users.filter(u=>u.role==='admin').length;const analysts=users.length-admins;document.getElementById('adminSummary').innerHTML=[['Total accounts',users.length,'All registered users'],['Administrators',admins,'Full console access'],['Study analysts',analysts,'Research workspace access']].map(([label,value,desc])=>'<div class="admin-stat"><span>'+label+'</span><strong>'+value+'</strong><small>'+desc+'</small></div>').join('');const query=(document.getElementById('adminSearch').value||'').toLowerCase();const filtered=users.filter(u=>(u.name+' '+u.email+' '+u.role).toLowerCase().includes(query));out.innerHTML=filtered.length?'<div class="tablewrap"><table><thead><tr><th>Account</th><th>Role</th><th>Joined</th><th>Access level</th></tr></thead><tbody>'+filtered.map(u=>'<tr><td><div class="account-cell"><span class="avatar">'+esc((u.name||'U').trim().charAt(0).toUpperCase())+'</span><span><b>'+esc(u.name)+'</b><small>'+esc(u.email)+'</small></span></div></td><td><span class="role-pill '+(u.role==='admin'?'role-admin':'role-analyst')+'">'+(u.role==='admin'?'Administrator':'Study Analyst')+'</span></td><td>'+esc(u.created_at)+'</td><td><select aria-label="Change role for '+esc(u.email)+'" onchange="setRole('+u.id+',this.value)"><option value="analyst" '+(u.role==='analyst'?'selected':'')+'>Study Analyst</option><option value="admin" '+(u.role==='admin'?'selected':'')+'>Administrator</option></select></td></tr>').join('')+'</tbody></table></div>':'<p class="empty-state">No accounts match this search.</p>';document.getElementById('adminCountLabel').textContent=users.length+' account'+(users.length===1?'':'s')}catch(e){out.textContent='Could not load accounts: '+e.message}}
async function setRole(id,role){try{const r=await fetch('/api/admin/users/'+id+'/role',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({role})});const d=await r.json();if(!r.ok)throw Error(d.detail||'Could not change role');await loadAdminUsers()}catch(e){alert(e.message);await loadAdminUsers()}}
currentUser={name:'Guest',role:'analyst'};showApp();
</script>
<script>
(function(){
 function mountHomeBrain(){
  const overview=document.getElementById('overview');
  const hero=overview&&overview.querySelector('.hero');
  if(!hero)return;
  // The source brain is inside Analytics, NOT inside Overview. Clone it into Home.
  let art=hero.querySelector('.brain-visual');
  if(!art){
   const source=document.querySelector('#analytics .brain-network-feature .brain-visual')||document.querySelector('.brain-network-feature .brain-visual');
   if(source){
    art=source.cloneNode(true);
    // Keep SVG definition IDs unique when both Home and Analytics show the brain.
    const idMap=new Map();
    art.querySelectorAll('[id]').forEach(el=>{const old=el.id;const next='home-'+old;idMap.set(old,next);el.id=next});
    art.querySelectorAll('*').forEach(el=>{
     for(const attr of Array.from(el.attributes||[])){
      let value=attr.value;
      for(const [old,next] of idMap){
       value=value.replaceAll('url(#'+old+')','url(#'+next+')');
       if((attr.name==='href'||attr.name==='xlink:href')&&value==='#'+old)value='#'+next;
      }
      if(value!==attr.value)el.setAttribute(attr.name,value);
     }
    });
    hero.appendChild(art);
   }
  }
  if(!art)return;
  art.style.setProperty('display','flex','important');
  art.style.setProperty('visibility','visible','important');
  art.style.setProperty('opacity','1','important');
  art.style.setProperty('min-height',window.innerWidth<=700?'270px':'340px','important');
  art.style.setProperty('grid-column',window.innerWidth<=700?'1':'2','important');
  art.style.setProperty('grid-row',window.innerWidth<=700?'2':'1','important');
  const svg=art.querySelector('svg');
  if(svg){svg.style.setProperty('display','block','important');svg.style.setProperty('visibility','visible','important');svg.style.setProperty('opacity','1','important')}
  const oldArt=hero.querySelector('.hero-art');if(oldArt)oldArt.remove();
  const copy=hero.querySelector(':scope > div:first-child');
  if(copy){
   const eyebrow=copy.querySelector('.eyebrow');if(eyebrow)eyebrow.textContent='COGNITIVE ANALYSIS WORKSPACE';
   const heading=copy.querySelector('h2');if(heading)heading.innerHTML='Brain Network <span class="hero-accent">Insights</span>';
   const paragraph=copy.querySelector('p');if(paragraph)paragraph.textContent='Explore cognitive patterns, patient similarities and network relationships using advanced analytics and machine learning.';
   const kpis=copy.querySelector('.hero-kpis');if(kpis)kpis.remove();
   const actions=copy.querySelector('.hero-actions');
   if(actions)actions.innerHTML='<button class="primary" onclick="tab(\'analytics\')">Open Cognitive Analysis &nbsp; →</button><button onclick="tab(\'network\')">♧ &nbsp; Explore Patient Network</button>';
  }
  if(!hero.querySelector('.hero-feature-rail')){
   const rail=document.createElement('div');rail.className='hero-feature-rail';
   rail.innerHTML='<div class="hero-feature"><span class="hero-feature-icon">⌘</span><div><b>Similarity Analysis</b><small>Find similar patients using multiple similarity metrics.</small></div></div><div class="hero-feature"><span class="hero-feature-icon">✿</span><div><b>K-means Clustering</b><small>Discover patient groups and patterns using ML clustering.</small></div></div><div class="hero-feature"><span class="hero-feature-icon">♧</span><div><b>Graph Metrics</b><small>Analyze network structure and connectivity.</small></div></div><div class="hero-feature"><span class="hero-feature-icon">♧</span><div><b>Cognitive Patterns</b><small>Explore MMSE, MoCA and cognitive feature contributions.</small></div></div>';
   hero.appendChild(rail);
  }
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mountHomeBrain,{once:true});else mountHomeBrain();
 window.addEventListener('load',mountHomeBrain);
 window.addEventListener('resize',function(){const art=document.querySelector('#overview>.hero .brain-visual');if(art){art.style.setProperty('min-height',window.innerWidth<=700?'270px':'340px','important');art.style.setProperty('grid-column',window.innerWidth<=700?'1':'2','important');art.style.setProperty('grid-row',window.innerWidth<=700?'2':'1','important')}});
})();
</script>
<script>
(function(){
 function initNeuralBackground(){
  if(document.getElementById('psn-neural-bg'))return;
  const canvas=document.createElement('canvas');canvas.id='psn-neural-bg';canvas.setAttribute('aria-hidden','true');document.body.prepend(canvas);
  const ctx=canvas.getContext('2d');if(!ctx)return;
  const reduced=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let w=0,h=0,dpr=1,pts=[],raf=0,last=0;
  function resize(){
   dpr=Math.min(window.devicePixelRatio||1,1.6);w=window.innerWidth;h=window.innerHeight;
   canvas.width=Math.round(w*dpr);canvas.height=Math.round(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);
   const count=Math.max(36,Math.min(90,Math.round(w*h/15500)));
   pts=Array.from({length:count},(_,i)=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.24,vy:(Math.random()-.5)*.24,r:Math.random()*1.7+.55,phase:Math.random()*6.28,seed:i}));
  }
  function draw(t){
   if(!document.body.contains(canvas))return;
   if(!reduced&&document.hidden){raf=requestAnimationFrame(draw);return}
   if(reduced&&last)return;last=t||1;
   ctx.clearRect(0,0,w,h);
   const drift=reduced?0:1;
   for(let i=0;i<pts.length;i++){
    const p=pts[i];p.x+=p.vx*drift;p.y+=p.vy*drift;
    if(p.x<-20)p.x=w+20;if(p.x>w+20)p.x=-20;if(p.y<-20)p.y=h+20;if(p.y>h+20)p.y=-20;
   }
   const max=w<650?105:155;
   for(let i=0;i<pts.length;i++){
    const a=pts[i];
    for(let j=i+1;j<pts.length;j++){
     const b=pts[j],dx=a.x-b.x,dy=a.y-b.y,dist=Math.sqrt(dx*dx+dy*dy);
     if(dist<max){
      const alpha=(1-dist/max)*.25;
      ctx.strokeStyle='rgba(37,166,255,'+alpha+')';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();
     }
    }
   }
   for(const p of pts){
    const pulse=reduced?1:(.65+.35*Math.sin((t||0)*.0012+p.phase));
    const radius=p.r*(.85+pulse*.4);
    const glow=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,10+radius*4);
    glow.addColorStop(0,'rgba(91,229,255,'+(.44*pulse)+')');glow.addColorStop(1,'rgba(20,120,255,0)');
    ctx.fillStyle=glow;ctx.beginPath();ctx.arc(p.x,p.y,10+radius*4,0,Math.PI*2);ctx.fill();
    ctx.fillStyle='rgba(125,224,255,'+(.42+pulse*.45)+')';ctx.beginPath();ctx.arc(p.x,p.y,radius,0,Math.PI*2);ctx.fill();
   }

   // Decorative flowing neural mesh on the left edge, matching the reference dashboard.
   const leftW=Math.min(w*.23,300), baseY=h*.76;
   ctx.save();
   for(let layer=0;layer<5;layer++){
    ctx.beginPath();
    for(let k=0;k<=48;k++){
     const x=leftW*k/48;
     const y=baseY-layer*24+Math.sin(k*.18+layer*.72+(reduced?0:(t||0)*.00035))*22+Math.sin(k*.075+layer)*17;
     if(k===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
    }
    ctx.strokeStyle='rgba(0,125,255,'+(0.13-layer*.014)+')';ctx.lineWidth=1;ctx.shadowColor='#087dff';ctx.shadowBlur=layer===0?9:3;ctx.stroke();
   }
   for(let k=0;k<95;k++){
    const x=(k*37.7)%Math.max(1,leftW), y=baseY-65+Math.sin(k*.37+(reduced?0:(t||0)*.0004))*78+Math.cos(k*.19)*48;
    const alpha=.16+.18*(.5+.5*Math.sin(k+(reduced?0:(t||0)*.001)));
    ctx.fillStyle='rgba(35,155,255,'+alpha+')';ctx.beginPath();ctx.arc(x,y,(k%5===0)?1.5:.8,0,Math.PI*2);ctx.fill();
   }
   ctx.restore();
   if(!reduced)raf=requestAnimationFrame(draw);
  }
  resize();window.addEventListener('resize',resize,{passive:true});
  if(reduced)draw(1);else raf=requestAnimationFrame(draw);
  const originalTab=window.tab;
  if(typeof originalTab==='function'&&!originalTab.__neuralWrapped){
   const wrapped=function(n){document.body.classList.toggle('psn-home-active',n==='overview');return originalTab.apply(this,arguments)};
   wrapped.__neuralWrapped=true;window.tab=wrapped;
  }
  const overview=document.getElementById('overview');
  document.body.classList.toggle('psn-home-active',!!overview&&!overview.classList.contains('hidden')&&overview.style.display!=='none');
  document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>document.body.classList.toggle('psn-home-active',b.dataset.tab==='overview')));
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initNeuralBackground,{once:true});else initNeuralBackground();
})();
</script>
</body></html>"""

@app.get("/", response_class=HTMLResponse)
def home(): return HTML
@app.get("/{full_path:path}", response_class=HTMLResponse)
def frontend_fallback(full_path: str):
    if full_path.startswith("api/"): raise HTTPException(404,"API route not found")
    return HTML
