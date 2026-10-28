"""Account, demo OTP recovery, and role-separated PSN portal routes.

Production notes:
- Set PSN_ADMIN_EMAIL and PSN_ADMIN_PASSWORD to bootstrap an administrator.
- Set PSN_SESSION_SECRET to a long random secret.
- Set PSN_DEMO_OTP=true only for demos; demo OTPs are returned to the UI, never sent by SMS.
- For real SMS delivery, integrate a provider and keep its API credentials in environment variables.
- SQLite storage is suitable for local demos. Vercel's /tmp is ephemeral; configure a durable database before relying on deployed accounts.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, EmailStr, field_validator

router = APIRouter()
DB_PATH = os.getenv("DATABASE_PATH", "/tmp/psn.db" if os.getenv("VERCEL") else "psn.db")
SESSION_SECRET = os.getenv("PSN_SESSION_SECRET", "local-demo-change-this-secret")
SESSION_COOKIE = "psn_session"
OTP_TTL_SECONDS = 300
SESSION_TTL_SECONDS = 43200
DEMO_OTP = os.getenv("PSN_DEMO_OTP", "true").lower() == "true"


def db_connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_auth_db():
    with db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS psn_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          full_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          mobile TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          created_at TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS psn_sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS psn_otp (
          mobile TEXT PRIMARY KEY,
          otp_hash TEXT NOT NULL,
          purpose TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0
        )""")
        admin_email = os.getenv("PSN_ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("PSN_ADMIN_PASSWORD", "")
        if admin_email and admin_password:
            existing = db.execute("SELECT id FROM psn_users WHERE email=?", (admin_email,)).fetchone()
            if existing:
                db.execute("UPDATE psn_users SET role='admin', active=1 WHERE email=?", (admin_email,))
            else:
                mobile = os.getenv("PSN_ADMIN_MOBILE", "+910000000000").strip()
                db.execute(
                    "INSERT INTO psn_users(full_name,email,mobile,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                    ("PSN Administrator", admin_email, mobile, hash_password(admin_password), "admin",
                     datetime.now(timezone.utc).isoformat())
                )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310000)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def otp_digest(mobile: str, otp: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), f"{mobile}:{otp}".encode(), hashlib.sha256).hexdigest()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def safe_user(row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["full_name"], "email": row["email"],
            "mobile": row["mobile"], "role": row["role"], "created_at": row["created_at"]}


def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    with db_connect() as db:
        row = db.execute("""SELECT u.* FROM psn_sessions s JOIN psn_users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
            (token_digest(token), int(time.time()))).fetchone()
    return row


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Please sign in to continue.")
    return user


def require_admin(request: Request):
    user = require_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access is required.")
    return user


class RegisterInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    mobile: str = Field(min_length=10, max_length=16)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("email")
    @classmethod
    def clean_email(cls, value):
        value = value.strip().lower()
        if "@" not in value or "." not in value.rsplit("@", 1)[-1]:
            raise ValueError("Enter a valid email address.")
        return value

    @field_validator("mobile")
    @classmethod
    def clean_mobile(cls, value):
        value = "".join(ch for ch in value if ch.isdigit() or ch == "+")
        if not value.startswith("+") or not 10 <= len(value.lstrip("+")) <= 15:
            raise ValueError("Use international format, e.g. +919876543210.")
        return value


class LoginInput(BaseModel):
    identity: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ForgotInput(BaseModel):
    mobile: str = Field(min_length=10, max_length=16)

    @field_validator("mobile")
    @classmethod
    def clean_mobile(cls, value):
        value = "".join(ch for ch in value if ch.isdigit() or ch == "+")
        if not value.startswith("+") or not 10 <= len(value.lstrip("+")) <= 15:
            raise ValueError("Use international format, e.g. +919876543210.")
        return value


class ResetInput(ForgotInput):
    otp: str = Field(pattern=r"^\d{6}$")
    new_password: str = Field(min_length=10, max_length=128)


def issue_session(response: Response, user_id: int):
    token = secrets.token_urlsafe(40)
    with db_connect() as db:
        db.execute("INSERT INTO psn_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                   (token_digest(token), user_id, int(time.time()) + SESSION_TTL_SECONDS))
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=bool(os.getenv("VERCEL")),
                        samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")


@router.on_event("startup")
def startup_auth():
    init_auth_db()


@router.post("/api/auth/register")
def register(payload: RegisterInput, response: Response):
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, "Name is required.")
    try:
        with db_connect() as db:
            cursor = db.execute("""INSERT INTO psn_users(full_name,email,mobile,password_hash,role,created_at)
                VALUES(?,?,?,?, 'user', ?)""",
                (name, payload.email, payload.mobile, hash_password(payload.password),
                 datetime.now(timezone.utc).isoformat()))
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email or mobile number already exists.")
    issue_session(response, user_id)
    with db_connect() as db:
        user = db.execute("SELECT * FROM psn_users WHERE id=?", (user_id,)).fetchone()
    return {"ok": True, "user": safe_user(user), "message": "Account created."}


@router.post("/api/auth/login")
def login(payload: LoginInput, response: Response):
    identity = payload.identity.strip()
    with db_connect() as db:
        user = db.execute("SELECT * FROM psn_users WHERE email=? COLLATE NOCASE OR mobile=?",
                          (identity, identity)).fetchone()
    if not user or not user["active"] or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(401, "Invalid sign-in details.")
    issue_session(response, user["id"])
    return {"ok": True, "user": safe_user(user), "message": "Signed in.",
            "redirect": "/admin" if user["role"] == "admin" else "/dashboard"}


@router.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        with db_connect() as db:
            db.execute("DELETE FROM psn_sessions WHERE token_hash=?", (token_digest(token),))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
def me(request: Request):
    user = require_user(request)
    return {"ok": True, "user": safe_user(user)}


@router.post("/api/auth/forgot/request")
def request_otp(payload: ForgotInput):
    mobile = payload.mobile
    with db_connect() as db:
        user = db.execute("SELECT id FROM psn_users WHERE mobile=? AND active=1", (mobile,)).fetchone()
        if not user:
            # Avoid account enumeration.
            return {"ok": True, "message": "If the number is registered, a recovery code has been generated."}
        otp = f"{secrets.randbelow(1000000):06d}"
        db.execute("""INSERT INTO psn_otp(mobile,otp_hash,purpose,expires_at,attempts) VALUES(?,?,?,?,0)
            ON CONFLICT(mobile) DO UPDATE SET otp_hash=excluded.otp_hash,purpose=excluded.purpose,
            expires_at=excluded.expires_at,attempts=0""",
            (mobile, otp_digest(mobile, otp), "reset", int(time.time()) + OTP_TTL_SECONDS))
    result = {"ok": True, "message": "Demo OTP generated. It expires in 5 minutes." if DEMO_OTP
              else "If the number is registered, recovery instructions will be sent."}
    if DEMO_OTP:
        result["demo_otp"] = otp
        result["demo_only"] = True
    else:
        # A production SMS provider must be configured before disabling demo mode.
        result["message"] = "SMS delivery is not configured. Set up an SMS provider before disabling demo mode."
    return result


@router.post("/api/auth/forgot/reset")
def reset_password(payload: ResetInput):
    with db_connect() as db:
        row = db.execute("SELECT * FROM psn_otp WHERE mobile=?", (payload.mobile,)).fetchone()
        if not row or row["purpose"] != "reset" or row["expires_at"] < int(time.time()):
            raise HTTPException(400, "Code expired or not found. Request a new code.")
        if row["attempts"] >= 5:
            db.execute("DELETE FROM psn_otp WHERE mobile=?", (payload.mobile,))
            raise HTTPException(429, "Too many attempts. Request a new code.")
        if not hmac.compare_digest(row["otp_hash"], otp_digest(payload.mobile, payload.otp)):
            db.execute("UPDATE psn_otp SET attempts=attempts+1 WHERE mobile=?", (payload.mobile,))
            raise HTTPException(400, "Incorrect verification code.")
        db.execute("UPDATE psn_users SET password_hash=? WHERE mobile=?",
                   (hash_password(payload.new_password), payload.mobile))
        db.execute("DELETE FROM psn_otp WHERE mobile=?", (payload.mobile,))
        db.execute("DELETE FROM psn_sessions WHERE user_id=(SELECT id FROM psn_users WHERE mobile=?)",
                   (payload.mobile,))
    return {"ok": True, "message": "Password updated. Please sign in again."}


@router.get("/api/user/dashboard")
def user_dashboard(request: Request):
    user = require_user(request)
    with db_connect() as db:
        sessions = db.execute("SELECT COUNT(*) n FROM psn_sessions WHERE user_id=? AND expires_at>?",
                              (user["id"], int(time.time()))).fetchone()["n"]
    return {"ok": True, "user": safe_user(user), "stats": {
        "saved_analyses": 0, "assessments": 0, "follow_ups": 0, "active_sessions": sessions
    }, "activity": [], "notice": "Connect user-owned analysis and assessment records to enable live personal metrics."}


@router.get("/api/admin/overview")
def admin_overview(request: Request):
    require_admin(request)
    with db_connect() as db:
        users = db.execute("SELECT COUNT(*) n FROM psn_users WHERE role='user'").fetchone()["n"]
        active = db.execute("SELECT COUNT(*) n FROM psn_users WHERE role='user' AND active=1").fetchone()["n"]
        admins = db.execute("SELECT COUNT(*) n FROM psn_users WHERE role='admin'").fetchone()["n"]
        recent = db.execute("SELECT id,full_name,email,mobile,role,created_at,active FROM psn_users ORDER BY id DESC LIMIT 8").fetchall()
        patient_count = db.execute("SELECT COUNT(*) n FROM patients").fetchone()["n"] if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='patients'").fetchone() else 0
    return {"ok": True, "stats": {"registered_users": users, "active_users": active,
            "administrators": admins, "patient_records": patient_count},
            "recent_users": [dict(id=r["id"], name=r["full_name"], email=r["email"],
             mobile=r["mobile"], role=r["role"], created_at=r["created_at"], active=bool(r["active"]))
             for r in recent]}


@router.get("/api/admin/users")
def admin_users(request: Request, q: str = "", limit: int = 50):
    require_admin(request)
    limit = max(1, min(limit, 100))
    with db_connect() as db:
        rows = db.execute("""SELECT id,full_name,email,mobile,role,created_at,active FROM psn_users
            WHERE full_name LIKE ? OR email LIKE ? OR mobile LIKE ? ORDER BY id DESC LIMIT ?""",
            (f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
    return {"ok": True, "users": [dict(id=r["id"], name=r["full_name"], email=r["email"],
        mobile=r["mobile"], role=r["role"], created_at=r["created_at"], active=bool(r["active"])) for r in rows]}


@router.post("/api/admin/users/{user_id}/toggle")
def toggle_user(user_id: int, request: Request):
    admin = require_admin(request)
    with db_connect() as db:
        target = db.execute("SELECT id,role,active FROM psn_users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found.")
        if target["role"] == "admin" or target["id"] == admin["id"]:
            raise HTTPException(400, "Administrator accounts cannot be disabled here.")
        db.execute("UPDATE psn_users SET active=? WHERE id=?", (0 if target["active"] else 1, user_id))
        if target["active"]:
            db.execute("DELETE FROM psn_sessions WHERE user_id=?", (user_id,))
    return {"ok": True, "active": not bool(target["active"])}


PORTAL_CSS = """
:root{color-scheme:dark;--bg:#08111f;--panel:rgba(17,31,51,.84);--line:rgba(151,180,220,.16);--text:#edf5ff;--muted:#9aaec8;--blue:#6faeff;--teal:#62e0cf;--danger:#ff8b9a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0%,#173858 0,transparent 38%),radial-gradient(ellipse at 0% 90%,#123b42 0,transparent 30%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;min-height:100vh}button,input{font:inherit}a{color:var(--blue);text-decoration:none}.shell{max-width:1200px;margin:auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:34px}.brand{display:flex;gap:12px;align-items:center;font-weight:750;font-size:18px}.brain{width:42px;height:42px;display:grid;place-items:center;border:1px solid #4b87ba;border-radius:14px;background:linear-gradient(135deg,#1c4265,#123b40);font-size:23px}.pill{border:1px solid var(--line);border-radius:999px;padding:7px 12px;color:var(--muted);font-size:12px}.hero{max-width:760px;margin:44px 0 28px}.eyebrow{color:var(--teal);letter-spacing:.14em;text-transform:uppercase;font-size:11px;font-weight:800}.hero h1{font-size:clamp(30px,5vw,48px);line-height:1.08;letter-spacing:-.04em;margin:12px 0}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.panel,.stat,.auth-card{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:22px;box-shadow:0 18px 50px #0002;backdrop-filter:blur(18px)}.stat small{color:var(--muted)}.stat strong{display:block;font-size:30px;margin:10px 0 2px}.content{display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-top:18px}.panel h2{font-size:16px;margin:0 0 16px}.bar{height:9px;background:#23364d;border-radius:99px;overflow:hidden;margin:12px 0}.bar span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--blue),var(--teal))}.list{display:grid;gap:10px}.userrow{display:flex;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);align-items:center}.userrow:last-child{border-bottom:0}.userrow small{display:block;color:var(--muted)}.btn{border:0;border-radius:12px;padding:11px 15px;background:linear-gradient(120deg,#75b4ff,#61dfcf);color:#061321;font-weight:800;cursor:pointer}.btn.secondary{background:#21364e;color:var(--text);border:1px solid var(--line)}.btn.danger{background:#482732;color:#ffc4cc}.btn:disabled{opacity:.5;cursor:wait}.field{display:grid;gap:7px;margin:13px 0}.field label{font-size:12px;color:#c4d3e8}.field input{width:100%;background:#081321;border:1px solid #30435c;border-radius:11px;padding:12px;color:var(--text);outline:none}.field input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #6faeff20}.auth-wrap{max-width:470px;margin:7vh auto}.auth-card{padding:30px}.auth-card h1{font-size:29px;letter-spacing:-.03em;margin:12px 0 4px}.msg{padding:12px;border-radius:12px;background:#18374a;color:#b8f7e9;margin:12px 0;word-break:break-word}.msg.error{background:#46232e;color:#ffc5cc}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}.search{max-width:300px}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-weight:600}.chart{height:180px;display:flex;align-items:end;gap:12px;padding-top:14px}.chartcol{flex:1;min-width:16px;display:flex;flex-direction:column;align-items:center;gap:8px;height:100%;justify-content:end}.chartbar{width:min(100%,38px);border-radius:9px 9px 3px 3px;background:linear-gradient(180deg,var(--teal),#4e86e9);min-height:6px}.chartcol small{font-size:10px;color:var(--muted)}.notice{border:1px solid #476b80;border-radius:12px;padding:13px;color:#bcd5e8;background:#11283b;font-size:12px;margin-top:16px}.hidden{display:none!important}@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.content{grid-template-columns:1fr}.shell{padding:18px}}@media(max-width:480px){.grid{grid-template-columns:1fr 1fr}.stat,.panel{padding:15px}.shell{padding:14px}.top{align-items:flex-start}.auth-card{padding:22px}.stat strong{font-size:25px}}
"""


def portal_page(kind: str) -> str:
    titles = {"admin": "Administrator workspace", "login": "Welcome back", "register": "Create your PSN account",
              "forgot": "Recover your account", "dashboard": "Your research workspace"}
    title = titles[kind]
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#08111f"><title>""" + title + """ · Patient Similarity Network</title><style>""" + PORTAL_CSS + """</style></head><body><main id="app" class="shell"><div class="top"><a class="brand" href="/"><span class="brain">🧠</span><span>Patient Similarity Network<small class="muted" style="display:block;font-size:11px;font-weight:500">Cognitive research workspace</small></span></a><span class="pill">SECURE WORKSPACE</span></div><div class="muted">Loading workspace…</div></main><script>
const kind = """ + json.dumps(kind) + """;
const app = document.getElementById('app');
const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url, options={}) {
  const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
  let data={}; try{data=await r.json()}catch{}
  if(!r.ok) throw new Error(data.detail||data.message||'Request failed');
  return data;
}
function shell(content, eyebrow='PATIENT SIMILARITY NETWORK') {
 app.innerHTML='<div class="top"><a class="brand" href="/"><span class="brain">🧠</span><span>Patient Similarity Network<small class="muted" style="display:block;font-size:11px;font-weight:500">Cognitive research workspace</small></span></a><div class="actions"><span class="pill">'+eyebrow+'</span></div></div>'+content;
}
function message(text,error=false){let el=document.getElementById('msg');if(el){el.className='msg'+(error?' error':'');el.textContent=text;el.classList.remove('hidden')}}
function authCard(title,desc,fields,button,footer,submit,extra=''){
 shell('<div class="auth-wrap"><section class="auth-card"><div class="eyebrow">SECURE ACCESS</div><h1>'+title+'</h1><p class="muted">'+desc+'</p><div id="msg" class="msg hidden"></div><form id="authform">'+fields+'<button class="btn" style="width:100%;margin-top:8px" type="submit">'+button+'</button></form>'+extra+'<p class="muted" style="font-size:13px;margin-top:20px">'+footer+'</p></section></div>');
 document.getElementById('authform').addEventListener('submit',async e=>{e.preventDefault();const btn=e.target.querySelector('button');btn.disabled=true;try{await submit(Object.fromEntries(new FormData(e.target).entries()))}catch(err){message(err.message,true)}finally{btn.disabled=false}});
}
const field=(name,label,type='text',placeholder='',attrs='')=>'<div class="field"><label for="'+name+'">'+label+'</label><input id="'+name+'" name="'+name+'" type="'+type+'" placeholder="'+placeholder+'" '+attrs+' required></div>';
function loginPage(){
 authCard('Welcome back','Sign in to access your personal cognitive research workspace.',field('identity','Email or mobile number','text','you@example.com or +919876543210')+field('password','Password','password','At least 10 characters'),
 'Sign in','New to PSN? <a href="/register">Create an account</a> · <a href="/forgot-password">Forgot password?</a>',
 async v=>{const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify(v)});location.href=d.redirect});
}
function registerPage(){
 authCard('Create your account','Your own workspace for research activity and saved insights.',field('name','Full name','text','Your name')+field('email','Email address','email','you@example.com')+field('mobile','Mobile number','tel','+919876543210','pattern="\\+[0-9]{10,15}"')+field('password','Create password','password','Use at least 10 characters','minlength="10"'),
 'Create account','Already registered? <a href="/login">Sign in</a>',
 async v=>{await api('/api/auth/register',{method:'POST',body:JSON.stringify(v)});location.href='/dashboard'});
}
function forgotPage(){
 authCard('Reset your password','Verify your registered mobile number, then choose a new password.',
 field('mobile','Mobile number','tel','+919876543210','pattern="\\+[0-9]{10,15}"')+
 '<button id="requestOtp" class="btn secondary" type="button" style="width:100%">Generate demo OTP</button>'+
 '<div id="otpzone" class="hidden">'+field('otp','6-digit verification code','text','123456','inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')+
 field('new_password','New password','password','At least 10 characters','minlength="10"')+'</div>',
 'Verify and reset','Remembered it? <a href="/login">Back to sign in</a>',
 async v=>{await api('/api/auth/forgot/reset',{method:'POST',body:JSON.stringify(v)});shell('<section class="auth-card"><h1>Password updated</h1><p class="muted">Your password was reset. Please sign in again.</p><a class="btn" href="/login">Go to sign in</a></section>')});
 document.getElementById('authform').querySelector('button[type=submit]').classList.add('hidden');
 document.getElementById('requestOtp').addEventListener('click',async()=>{try{const mobile=document.getElementById('mobile').value;const d=await api('/api/auth/forgot/request',{method:'POST',body:JSON.stringify({mobile})});message(d.message);if(d.demo_otp)message(d.message+' Demo OTP: '+d.demo_otp);document.getElementById('otpzone').classList.remove('hidden');document.getElementById('authform').querySelector('button[type=submit]').classList.remove('hidden');document.getElementById('authform').querySelector('button[type=submit]').textContent='Reset password'}catch(err){message(err.message,true)}});
 document.getElementById('authform').addEventListener('submit',async e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.target).entries());try{await api('/api/auth/forgot/reset',{method:'POST',body:JSON.stringify(v)});shell('<section class="auth-card"><h1>Password updated</h1><p class="muted">Your password was reset. Please sign in again.</p><a class="btn" href="/login">Go to sign in</a></section>')}catch(err){message(err.message,true)}});
}
async function dashboardPage(){
 try{
 const d=await api('/api/user/dashboard');const u=d.user;
 shell('<section class="hero"><div class="eyebrow">PERSONAL WORKSPACE</div><h1>Good to see you, '+esc(u.name.split(' ')[0])+'.</h1><p class="muted">Your research activity, assessment history, and saved insights in one place.</p></section><div class="grid"><article class="stat"><small>Saved analyses</small><strong>'+d.stats.saved_analyses+'</strong><span class="muted">Your workspace</span></article><article class="stat"><small>Assessments</small><strong>'+d.stats.assessments+'</strong><span class="muted">Completed sessions</span></article><article class="stat"><small>Follow-ups</small><strong>'+d.stats.follow_ups+'</strong><span class="muted">Planned reviews</span></article><article class="stat"><small>Account status</small><strong style="font-size:21px;color:var(--teal)">Active</strong><span class="muted">Secure sign-in</span></article></div><div class="content"><section class="panel"><h2>Workspace overview</h2><p class="muted">Your personal research workspace is ready. Saved analysis and assessment counts will populate when those existing PSN records are linked to your account.</p><div class="bar"><span style="width:72%"></span></div><small class="muted">Profile · '+esc(u.email)+'</small><div class="actions"><a class="btn" href="/">Open PSN research</a><button class="btn secondary" id="profile">Account details</button></div></section><section class="panel"><h2>Recent activity</h2><p class="muted">No personal activity has been linked yet.</p><div class="notice">'+esc(d.notice)+'</div></section></div><div class="actions"><button class="btn secondary" id="logout">Sign out</button></div>','USER DASHBOARD');
 document.getElementById('profile').onclick=()=>alert('Name: '+u.name+'\nEmail: '+u.email+'\nMobile: '+u.mobile+'\nMember since: '+u.created_at.slice(0,10));
 document.getElementById('logout').onclick=async()=>{await api('/api/auth/logout',{method:'POST'});location.href='/login'};
 }catch(e){location.href='/login'}
}
async function adminPage(){
 try{
 const [d,ud]=await Promise.all([api('/api/admin/overview'),api('/api/admin/users')]);const s=d.stats;
 shell('<section class="hero"><div class="eyebrow">ADMINISTRATION · LIVE ACCOUNT METRICS</div><h1>Admin command center</h1><p class="muted">Manage access and monitor your PSN workspace. Administrator-only data is protected by server-side role checks.</p></section><div class="grid"><article class="stat"><small>Registered users</small><strong>'+s.registered_users+'</strong><span class="muted">All user accounts</span></article><article class="stat"><small>Active users</small><strong>'+s.active_users+'</strong><span class="muted">Enabled accounts</span></article><article class="stat"><small>Administrators</small><strong>'+s.administrators+'</strong><span class="muted">Privileged accounts</span></article><article class="stat"><small>Patient records</small><strong>'+s.patient_records+'</strong><span class="muted">Current database</span></article></div><div class="content"><section class="panel"><h2>Account growth · registered users</h2><div class="chart">'+[12,20,28,38,48,62,72].map((h,i)=>'<div class="chartcol"><div class="chartbar" style="height:'+Math.max(10,Math.min(100,h*(s.registered_users?Math.min(s.registered_users/4,1.3):.35)))+'%"></div><small>'+['M','T','W','T','F','S','S'][i]+'</small></div>').join('')+'</div><p class="muted" style="font-size:12px">Illustrative activity visualization; daily signup history is not yet stored.</p></section><section class="panel"><h2>Account health</h2><p class="muted">Enabled accounts</p><div class="bar"><span style="width:'+(s.registered_users?Math.round(s.active_users/s.registered_users*100):0)+'%"></span></div><strong>'+ (s.registered_users?Math.round(s.active_users/s.registered_users*100):0)+'%</strong><p class="muted">of registered users are active</p><div class="notice">Patient counts reflect the current configured database. Synthetic research records are not real patient diagnoses.</div></section></div><section class="panel" style="margin-top:16px"><div class="top" style="margin-bottom:8px"><h2 style="margin:0">User management</h2><input id="search" class="field search" style="margin:0" placeholder="Search name, email, mobile"></div><div class="tablewrap"><table><thead><tr><th>User</th><th>Mobile</th><th>Role</th><th>Status</th><th>Action</th></tr></thead><tbody id="users"></tbody></table></div></section><div class="actions"><a class="btn" href="/">Open main PSN</a><button class="btn secondary" id="logout">Sign out</button></div>','ADMIN CONSOLE');
 let users=ud.users;const render=()=>{const q=document.getElementById('search').value.toLowerCase();document.getElementById('users').innerHTML=users.filter(u=>(u.name+' '+u.email+' '+u.mobile).toLowerCase().includes(q)).map(u=>'<tr><td><strong>'+esc(u.name)+'</strong><small>'+esc(u.email)+'</small></td><td>'+esc(u.mobile)+'</td><td>'+esc(u.role)+'</td><td><span class="pill">'+(u.active?'Active':'Disabled')+'</span></td><td>'+(u.role==='admin'?'—':'<button class="btn '+(u.active?'danger':'secondary')+'" data-id="'+u.id+'">'+(u.active?'Disable':'Enable')+'</button>')+'</td></tr>').join('')||'<tr><td colspan="5" class="muted">No users found.</td></tr>';document.querySelectorAll('[data-id]').forEach(b=>b.onclick=async()=>{try{await api('/api/admin/users/'+b.dataset.id+'/toggle',{method:'POST'});const fresh=await api('/api/admin/users');users=fresh.users;render()}catch(e){alert(e.message)}})};
 render();document.getElementById('search').oninput=render;
 document.getElementById('logout').onclick=async()=>{await api('/api/auth/logout',{method:'POST'});location.href='/admin'};
 }catch(e){if(e.message.includes('Administrator')){shell('<section class="auth-card"><h1>Admin access denied</h1><p class="muted">This account is not authorized for the administrator portal.</p><a href="/login">Sign in as a different user</a></section>')}else{adminLogin()}}
}
function adminLogin(){
 authCard('Administrator sign in','The admin console is separate from the public PSN home page.',field('identity','Admin email or mobile','text','admin@example.com')+field('password','Admin password','password','Your admin password'),'Enter admin console','Not an administrator? <a href="/">Return to PSN home</a>',
 async v=>{const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify(v)});if(d.user.role!=='admin'){await api('/api/auth/logout',{method:'POST'});throw new Error('This account does not have administrator privileges.')}location.href='/admin'});
}
(async()=>{if(kind==='login')loginPage();else if(kind==='register')registerPage();else if(kind==='forgot')forgotPage();else if(kind==='dashboard')await dashboardPage();else if(kind==='admin'){try{const m=await api('/api/auth/me');if(m.user.role!=='admin'){shell('<section class="auth-card"><h1>Admin access denied</h1><p class="muted">This account is not authorized for this portal.</p><a href="/dashboard">Go to your dashboard</a></section>');return}await adminPage()}catch{adminLogin()}}})();
</script></body></html>"""


@router.get("/admin", response_class=HTMLResponse)
def admin_portal():
    return HTMLResponse(portal_page("admin"))


@router.get("/register", response_class=HTMLResponse)
def register_page():
    return HTMLResponse(portal_page("register"))


@router.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(portal_page("login"))


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_page():
    return HTMLResponse(portal_page("forgot"))


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return HTMLResponse(portal_page("dashboard"))
