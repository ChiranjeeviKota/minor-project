"""Additional research analytics for Patient Similarity Network."""
from __future__ import annotations
import csv, io, math
from collections import Counter, defaultdict, deque
from datetime import date, datetime
from statistics import mean, median, pstdev
from typing import Any, Callable, Sequence
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, Response

DOMAIN_LABELS = {"memory":"Memory","attention":"Attention","executive":"Executive function","language":"Language","visuospatial":"Visuospatial","processing_speed":"Processing speed","orientation":"Orientation"}
EXPECTED_DIAGNOSES = {"Healthy","MCI","Alzheimer's"}
WEIGHTS = {"memory":.22,"attention":.14,"executive":.18,"language":.12,"visuospatial":.12,"processing_speed":.10,"orientation":.12}
DISCLAIMER = "Exploratory research output from a software demonstration. Records may be synthetic. Not a diagnosis or treatment recommendation."

def finite_number(value: Any) -> bool:
    if isinstance(value, bool): return False
    try: return math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError): return False

def numeric_values(values: Sequence[Any]) -> list[float]:
    return [float(v) for v in values if finite_number(v)]

def average(values: Sequence[Any]) -> float | None:
    vals=numeric_values(values)
    return round(mean(vals),2) if vals else None

def valid_iso_date(value: Any) -> bool:
    try: datetime.strptime(str(value),"%Y-%m-%d"); return True
    except (TypeError,ValueError): return False

def profile_summary(patients: Sequence[dict[str,Any]], domains: Sequence[str]) -> dict[str,Any]:
    result={}
    for d in domains:
        vals=numeric_values([p.get(d) for p in patients])
        result[d]={"label":DOMAIN_LABELS.get(d,d.replace("_"," ").title()),"count":len(vals),
          "mean":round(mean(vals),2) if vals else None,"median":round(median(vals),2) if vals else None,
          "std_dev":round(pstdev(vals),2) if len(vals)>1 else (0.0 if vals else None),
          "min":round(min(vals),2) if vals else None,"max":round(max(vals),2) if vals else None}
    return result

def cohort_summary(patients: Sequence[dict[str,Any]], domains: Sequence[str]) -> dict[str,Any]:
    groups=defaultdict(list)
    for p in patients: groups[str(p.get("diagnosis") or "Unspecified")].append(p)
    cohorts=[]
    for label,group in sorted(groups.items()):
        cohorts.append({"diagnosis":label,"count":len(group),"mean_mmse":average([p.get("mmse") for p in group]),
          "mean_moca":average([p.get("moca") for p in group]),"mean_age":average([p.get("age") for p in group]),
          "domain_means":{d:average([p.get(d) for p in group]) for d in domains}})
    return {"cohorts":cohorts,"total_patients":len(patients),"domains":list(domains),"disclaimer":DISCLAIMER}

def quality_audit(patients: Sequence[dict[str,Any]], domains: Sequence[str]) -> dict[str,Any]:
    required=["patient_code","age","sex","diagnosis","mmse","moca",*domains]
    codes=Counter(str(p.get("patient_code") or "").strip() for p in patients)
    duplicates=sorted(code for code,n in codes.items() if code and n>1)
    findings=[]; missing_count=range_count=0
    for p in patients:
        code=str(p.get("patient_code") or "row-"+str(p.get("id","?")))
        missing=[k for k in required if p.get(k) is None or p.get(k)==""]
        if missing:
            missing_count+=len(missing); findings.append({"patient_code":code,"severity":"warning","type":"missing_fields","fields":missing,"message":"Required fields are missing or empty."})
        invalid=[]
        for field,low,high in [("age",18,120),("mmse",0,30),("moca",0,30),*((d,0,100) for d in domains)]:
            value=p.get(field)
            if value is not None and value!="" and (not finite_number(value) or not low<=float(value)<=high):
                invalid.append({"field":field,"value":str(value),"allowed":[low,high]})
        if invalid:
            range_count+=len(invalid); findings.append({"patient_code":code,"severity":"error","type":"out_of_range","fields":invalid,"message":"Numeric value falls outside expected demo ranges."})
        diagnosis=str(p.get("diagnosis") or "")
        if diagnosis and diagnosis not in EXPECTED_DIAGNOSES:
            findings.append({"patient_code":code,"severity":"info","type":"unexpected_cohort","fields":["diagnosis"],"message":"Diagnosis label is outside standard demo cohort labels."})
        if p.get("visit_date") and not valid_iso_date(p["visit_date"]):
            findings.append({"patient_code":code,"severity":"warning","type":"invalid_date","fields":["visit_date"],"message":"Date should use YYYY-MM-DD format."})
    for code in duplicates:
        findings.append({"patient_code":code,"severity":"error","type":"duplicate_patient_code","fields":["patient_code"],"message":"Patient code occurs more than once."})
    errors=sum(f["severity"]=="error" for f in findings); warnings=sum(f["severity"]=="warning" for f in findings)
    return {"total_patients":len(patients),"findings_count":len(findings),"missing_values_count":missing_count,
      "out_of_range_values_count":range_count,"duplicate_patient_codes":duplicates,"error_count":errors,"warning_count":warnings,
      "status":"review_required" if errors else ("review_suggested" if warnings else "passed"),
      "findings":findings[:500],"findings_truncated":len(findings)>500,
      "disclaimer":"Format/range checks do not validate clinical accuracy."}

def network_metrics(patients: Sequence[dict[str,Any]], similarity_fn: Callable[[dict[str,Any],dict[str,Any]],float], threshold: float) -> dict[str,Any]:
    if not 0<=threshold<=100: raise ValueError("threshold must be between 0 and 100")
    ids=[p.get("id",p.get("patient_code")) for p in patients]; adj={pid:set() for pid in ids}; edges=[]
    for i,left in enumerate(patients):
        for right in patients[i+1:]:
            score=float(similarity_fn(left,right))
            if score>=threshold:
                a=left.get("id",left.get("patient_code")); b=right.get("id",right.get("patient_code"))
                adj[a].add(b); adj[b].add(a); edges.append({"source":a,"target":b,"weight":round(score,1)})
    degrees=[]
    for p in patients:
        pid=p.get("id",p.get("patient_code")); degree=len(adj[pid])
        degrees.append({"patient_id":pid,"patient_code":p.get("patient_code"),"diagnosis":p.get("diagnosis"),"degree":degree,
          "degree_centrality":round(degree/(len(patients)-1),4) if len(patients)>1 else 0})
    visited=set(); components=[]
    for pid in ids:
        if pid in visited: continue
        queue=deque([pid]); visited.add(pid); component=[]
        while queue:
            current=queue.popleft(); component.append(current)
            for neighbor in adj[current]:
                if neighbor not in visited: visited.add(neighbor); queue.append(neighbor)
        components.append(component)
    components.sort(key=len,reverse=True); possible=len(patients)*(len(patients)-1)/2
    return {"threshold":threshold,"nodes":len(patients),"edge_count":len(edges),"edges":edges,"density":round(len(edges)/possible,4) if possible else 0,
      "average_degree":round(sum(map(len,adj.values()))/len(patients),2) if patients else 0,
      "components":[{"size":len(c),"patient_ids":c} for c in components],
      "top_degree":sorted(degrees,key=lambda p:(-p["degree"],str(p["patient_code"])))[:15],
      "disclaimer":"Connectivity reflects the selected similarity threshold, not a biological connection."}

def compare_patients(patients: Sequence[dict[str,Any]], patient_ids: Sequence[int], domains: Sequence[str]) -> dict[str,Any]:
    if not 2<=len(patient_ids)<=8: raise ValueError("Select between two and eight patient IDs.")
    if len(set(patient_ids))!=len(patient_ids): raise ValueError("Patient IDs must be unique.")
    lookup={int(p["id"]):p for p in patients if p.get("id") is not None}
    missing=[pid for pid in patient_ids if pid not in lookup]
    if missing: raise LookupError("Patient IDs not found: "+", ".join(map(str,missing)))
    selected=[lookup[pid] for pid in patient_ids]; rows=[]
    for d in domains:
        vals=[float(p[d]) if finite_number(p.get(d)) else None for p in selected]; valid=[v for v in vals if v is not None]
        rows.append({"domain":d,"label":DOMAIN_LABELS.get(d,d.title()),"values":vals,
          "mean":round(mean(valid),2) if valid else None,"range":round(max(valid)-min(valid),2) if valid else None,
          "weight_percent":round(WEIGHTS.get(d,1/len(domains))*100,1)})
    rows.sort(key=lambda r:(-(r["range"] or 0),r["domain"]))
    return {"patients":[{"id":p.get("id"),"patient_code":p.get("patient_code"),"diagnosis":p.get("diagnosis"),
      "age":p.get("age"),"mmse":p.get("mmse"),"moca":p.get("moca")} for p in selected],
      "domains":rows,"patient_count":len(selected),"disclaimer":DISCLAIMER}

def visit_trends(connect: Callable[[],Any], patients: Sequence[dict[str,Any]]) -> dict[str,Any]:
    db=connect()
    try:
        rows=db.execute("SELECT v.visit_date,v.mmse,v.moca,v.memory,v.attention,v.executive,v.language,v.visuospatial,v.processing_speed,v.orientation,p.diagnosis FROM visits v LEFT JOIN patients p ON p.id=v.patient_id ORDER BY v.visit_date,v.id").fetchall()
        visits=[dict(r) for r in rows]
    finally: db.close()
    grouped=defaultdict(list)
    for v in visits:
        if valid_iso_date(v.get("visit_date")): grouped[str(v["visit_date"])].append(v)
    timeline=[]
    for day,group in sorted(grouped.items()):
        timeline.append({"date":day,"visit_count":len(group),"mean_mmse":average([v.get("mmse") for v in group]),
          "mean_moca":average([v.get("moca") for v in group]),"domain_means":{d:average([v.get(d) for v in group]) for d in DOMAIN_LABELS}})
    return {"total_visits":len(visits),"patient_count":len(patients),"timeline":timeline,"disclaimer":"Aggregate trends are descriptive; visit schedules may differ."}

def csv_template(domains: Sequence[str]) -> str:
    fields=["patient_code","age","sex","diagnosis","mmse","moca",*domains]; output=io.StringIO(newline="")
    writer=csv.DictWriter(output,fieldnames=fields,lineterminator="\n"); writer.writeheader()
    example={"patient_code":"EXAMPLE-REMOVE-ME","age":70,"sex":"Unknown","diagnosis":"MCI","mmse":24,"moca":22}
    example.update({d:60 for d in domains}); writer.writerow(example); return output.getvalue()

def report_payload(patients,domains,threshold,similarity_fn):
    return {"schema_version":"1.0","generated_on":date.today().isoformat(),"project":"Patient Similarity Network",
      "summary":{"patient_count":len(patients),"cohort_count":len({p.get("diagnosis") for p in patients})},
      "quality":quality_audit(patients,domains),"cohorts":cohort_summary(patients,domains),
      "domain_summary":profile_summary(patients,domains),"network":network_metrics(patients,similarity_fn,threshold),
      "disclaimer":DISCLAIMER}

def build_advanced_router(connect,all_patients,similarity,domains):
    router=APIRouter()
    @router.get("/api/research/quality")
    def get_quality(): return quality_audit(all_patients(),domains)
    @router.get("/api/research/cohorts")
    def get_cohorts(): return cohort_summary(all_patients(),domains)
    @router.get("/api/research/domain-summary")
    def get_domain_summary():
        patients=all_patients(); return {"patient_count":len(patients),"domains":profile_summary(patients,domains),"disclaimer":DISCLAIMER}
    @router.get("/api/research/centrality")
    def get_centrality(threshold:float=85):
        if not 0<=threshold<=100: raise HTTPException(400,"Threshold must be between 0 and 100.")
        return network_metrics(all_patients(),lambda a,b:similarity(a,b),threshold)
    @router.get("/api/research/compare")
    def get_comparison(patient_ids:str):
        try: return compare_patients(all_patients(),[int(x.strip()) for x in patient_ids.split(",") if x.strip()],domains)
        except ValueError as e: raise HTTPException(400,str(e))
        except LookupError as e: raise HTTPException(404,str(e))
    @router.get("/api/research/trends")
    def get_trends(): return visit_trends(connect,all_patients())
    @router.get("/api/research/overview")
    def get_overview(threshold:float=85):
        if not 0<=threshold<=100: raise HTTPException(400,"Threshold must be between 0 and 100.")
        patients=all_patients()
        return {"generated_on":date.today().isoformat(),"quality":quality_audit(patients,domains),
          "cohorts":cohort_summary(patients,domains),"domain_summary":profile_summary(patients,domains),
          "network":network_metrics(patients,lambda a,b:similarity(a,b),threshold),"disclaimer":DISCLAIMER}
    @router.get("/api/research/report.json")
    def get_report(threshold:float=85):
        if not 0<=threshold<=100: raise HTTPException(400,"Threshold must be between 0 and 100.")
        return JSONResponse(report_payload(all_patients(),domains,threshold,similarity),
          headers={"Content-Disposition":'attachment; filename="psn-research-report.json"'})
    @router.get("/api/research/csv-template")
    def get_csv_template():
        return Response(csv_template(domains),media_type="text/csv; charset=utf-8",
          headers={"Content-Disposition":'attachment; filename="psn-import-template.csv"'})
    return router

def advanced_ui_script() -> str:
    return r"""
<script id="psn-advanced-research-ui">
(function(){
 function mount(){
  var root=document.getElementById('research');
  if(!root||document.getElementById('psnResearchToolkit'))return;
  var panel=document.createElement('section');panel.id='psnResearchToolkit';
  panel.innerHTML=['<div class="section-heading"><div><div class="eyebrow">RESEARCH TOOLKIT</div><h2>Data quality & cohort insights</h2></div></div>',
   '<p class="muted">Run transparent data checks, inspect network centrality, explore follow-up trends and export reports.</p>',
   '<div class="toolbar" role="group" aria-label="Research toolkit actions">',
   '<button type="button" data-psn-action="quality">Check data quality</button><button type="button" data-psn-action="cohorts">Cohort summary</button>',
   '<button type="button" data-psn-action="centrality">Network centrality</button><button type="button" data-psn-action="trends">Follow-up trends</button>',
   '<button type="button" data-psn-action="overview" class="primary">Full research overview</button>',
   '<a class="btn" href="/api/research/report.json" target="_blank" rel="noopener">Export JSON report</a><a class="btn" href="/api/research/csv-template" target="_blank" rel="noopener">CSV template</a></div>',
   '<p id="psnResearchStatus" class="muted" role="status" aria-live="polite">Choose an action to load current API results.</p><div id="psnResearchOutput" aria-live="polite"></div>',
   '<p class="muted" style="font-size:11px">Research demo only. Similarity and clustering are not clinical conclusions.</p>'].join('');
  root.appendChild(panel);
  var status=panel.querySelector('#psnResearchStatus'),out=panel.querySelector('#psnResearchOutput');
  function esc(v){return String(v==null?'—':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  function cards(items){return '<div class="cards">'+items.map(function(x){return '<article class="card"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><small>'+esc(x[2])+'</small></article>'}).join('')+'</div>'}
  function render(d,k){
   if(k==='quality'){out.innerHTML=cards([['Audit status',d.status,'Required fields and ranges'],['Findings',d.findings_count,'Flagged items'],['Out of range',d.out_of_range_values_count,'Numeric range issues'],['Duplicate codes',d.duplicate_patient_codes.length,'Repeated identifiers']])+'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Severity</th><th>Finding</th></tr></thead><tbody>'+(d.findings||[]).map(function(f){return '<tr><td>'+esc(f.patient_code)+'</td><td>'+esc(f.severity)+'</td><td>'+esc(f.message)+'</td></tr>'}).join('')+'</tbody></table></div>'}
   else if(k==='cohorts'){out.innerHTML='<div class="tablewrap"><table><thead><tr><th>Cohort</th><th>Patients</th><th>Mean MMSE</th><th>Mean MoCA</th><th>Mean age</th></tr></thead><tbody>'+d.cohorts.map(function(c){return '<tr><td>'+esc(c.diagnosis)+'</td><td>'+esc(c.count)+'</td><td>'+esc(c.mean_mmse)+'</td><td>'+esc(c.mean_moca)+'</td><td>'+esc(c.mean_age)+'</td></tr>'}).join('')+'</tbody></table></div>'}
   else if(k==='centrality'){out.innerHTML=cards([['Nodes',d.nodes,'Patients'],['Edges',d.edge_count,'At '+d.threshold+'%'],['Density',d.density,'Possible connections'],['Components',d.components.length,'Connected groups']])+'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Cohort</th><th>Connections</th><th>Centrality</th></tr></thead><tbody>'+d.top_degree.map(function(p){return '<tr><td>'+esc(p.patient_code)+'</td><td>'+esc(p.diagnosis)+'</td><td>'+esc(p.degree)+'</td><td>'+esc(p.degree_centrality)+'</td></tr>'}).join('')+'</tbody></table></div>'}
   else if(k==='trends'){out.innerHTML='<div class="tablewrap"><table><thead><tr><th>Date</th><th>Visits</th><th>Mean MMSE</th><th>Mean MoCA</th></tr></thead><tbody>'+d.timeline.map(function(v){return '<tr><td>'+esc(v.date)+'</td><td>'+esc(v.visit_count)+'</td><td>'+esc(v.mean_mmse)+'</td><td>'+esc(v.mean_moca)+'</td></tr>'}).join('')+'</tbody></table></div>'}
   else{out.innerHTML=cards([['Patients',d.cohorts.total_patients,'Loaded records'],['Quality flags',d.quality.findings_count,'Review audit'],['Network edges',d.network.edge_count,'At '+d.network.threshold+'%'],['Cohorts',d.cohorts.cohorts.length,'Observed labels']])+'<div class="feature-grid">'+Object.keys(d.domain_summary).map(function(key){var x=d.domain_summary[key];return '<article class="feature-card"><b>'+esc(x.label)+'</b><div class="metric"><span>Mean</span><b>'+esc(x.mean)+'</b></div><div class="metric"><span>Range</span><b>'+esc(x.min)+' – '+esc(x.max)+'</b></div></article>'}).join('')+'</div>'}
  }
  var urls={quality:'/api/research/quality',cohorts:'/api/research/cohorts',centrality:'/api/research/centrality?threshold=85',trends:'/api/research/trends',overview:'/api/research/overview?threshold=85'};
  panel.querySelectorAll('[data-psn-action]').forEach(function(b){b.addEventListener('click',async function(){var kind=b.dataset.psnAction;b.disabled=true;status.textContent='Loading '+kind+'…';try{var r=await fetch(urls[kind],{cache:'no-store'}),d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');render(d,kind);status.textContent='Results refreshed. Descriptive only, not clinical advice.'}catch(e){status.textContent='Could not load results: '+e.message;out.textContent='Please check the API and try again.'}finally{b.disabled=false}})});
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();window.addEventListener('load',mount);
})();
</script>
"""
