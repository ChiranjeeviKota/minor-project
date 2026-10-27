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
    add_v2_routes(router, all_patients, similarity, domains)
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
   '<button type="button" data-psn-action="centrality">Network centrality</button><button type="button" data-psn-action="trends">Follow-up trends</button><button type="button" data-psn-action="correlations">Domain correlations</button><button type="button" data-psn-action="distributions">Score distributions</button><button type="button" data-psn-action="outliers">Outlier screen</button>',
   '<button type="button" data-psn-action="overview" class="primary">Full research overview</button><label for="psnCsvText">CSV preview (paste CSV text; preview only)</label><textarea id="psnCsvText" rows="4" style="width:100%;box-sizing:border-box" placeholder="patient_code,age,sex,diagnosis,mmse,moca,memory,attention,executive,language,visuospatial,processing_speed,orientation"></textarea><button type="button" data-psn-action="csvpreview">Validate CSV preview</button><label for="psnCompareIds">Compare IDs</label><input id="psnCompareIds" aria-label="Comma-separated patient IDs" placeholder="1,2" inputmode="numeric" style="width:110px"><button type="button" data-psn-action="compare">Compare profiles</button>',
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
   else if(k==='compare'){out.innerHTML='<h3>Selected patients</h3><div class="feature-grid">'+d.patients.map(function(p){return '<article class="feature-card"><b>'+esc(p.patient_code)+'</b><div class="metric"><span>Cohort</span><b>'+esc(p.diagnosis)+'</b></div><div class="metric"><span>MMSE / MoCA</span><b>'+esc(p.mmse)+' / '+esc(p.moca)+'</b></div></article>'}).join('')+'</div><h3>Largest domain differences</h3><div class="tablewrap"><table><thead><tr><th>Domain</th><th>Mean score</th><th>Range</th><th>Weight</th></tr></thead><tbody>'+d.domains.map(function(x){return '<tr><td>'+esc(x.label)+'</td><td>'+esc(x.mean)+'</td><td>'+esc(x.range)+'</td><td>'+esc(x.weight_percent)+'%</td></tr>'}).join('')+'</tbody></table></div>'}
   else if(k==='correlations'){out.innerHTML='<div class="tablewrap"><table><thead><tr><th>Domain</th>'+d.domains.map(function(x){return '<th>'+esc(x)+'</th>'}).join('')+'</tr></thead><tbody>'+d.domains.map(function(x){return '<tr><td>'+esc(x)+'</td>'+d.domains.map(function(y){return '<td>'+esc(d.matrix[x][y])+' <small>n='+esc(d.sample_counts[x][y])+'</small></td>'}).join('')+'</tr>'}).join('')+'</tbody></table></div><p class="muted">'+esc(d.interpretation)+'</p>'}
   else if(k==='distributions'){out.innerHTML='<div class="feature-grid">'+Object.keys(d.domains).map(function(key){var x=d.domains[key];return '<article class="feature-card"><b>'+esc(x.label)+'</b><div class="metric"><span>Mean</span><b>'+esc(x.mean)+'</b></div>'+x.bins.map(function(bin){return '<div class="metric"><span>'+esc(bin.range)+'</span><b>'+esc(bin.count)+'</b></div>'}).join('')+'</article>'}).join('')+'</div>'}
   else if(k==='outliers'){out.innerHTML=cards([['Statistical flags',d.outlier_count,'IQR screening'],['Skipped domains',d.skipped_domains.length,'Insufficient observations']])+'<div class="tablewrap"><table><thead><tr><th>Patient</th><th>Domain</th><th>Score</th><th>Flag</th></tr></thead><tbody>'+d.findings.map(function(x){return '<tr><td>'+esc(x.patient_code)+'</td><td>'+esc(x.domain)+'</td><td>'+esc(x.value)+'</td><td>'+esc(x.direction)+'</td></tr>'}).join('')+'</tbody></table></div><p class="muted">'+esc(d.disclaimer)+'</p>'}
   else if(k==='csvpreview'){out.innerHTML=cards([['CSV rows',d.row_count,'Previewed'],['Valid rows',d.valid_rows,'Format checks passed'],['Invalid rows',d.invalid_rows,'Review before import'],['Can import',d.can_import?'Yes':'No','Preview does not save data']])+'<div class="tablewrap"><table><thead><tr><th>Row</th><th>Patient code</th><th>Status</th></tr></thead><tbody>'+d.preview.map(function(x){return '<tr><td>'+esc(x.row)+'</td><td>'+esc(x.patient_code)+'</td><td>'+esc(x.valid?'Valid':'Invalid')+'</td></tr>'}).join('')+'</tbody></table></div><p class="muted">'+(d.findings||[]).map(function(x){return esc('Row '+x.row+': '+x.message)}).join(' · ')+'</p>'}
   else if(k==='trends'){out.innerHTML='<div class="tablewrap"><table><thead><tr><th>Date</th><th>Visits</th><th>Mean MMSE</th><th>Mean MoCA</th></tr></thead><tbody>'+d.timeline.map(function(v){return '<tr><td>'+esc(v.date)+'</td><td>'+esc(v.visit_count)+'</td><td>'+esc(v.mean_mmse)+'</td><td>'+esc(v.mean_moca)+'</td></tr>'}).join('')+'</tbody></table></div>'}
   else{out.innerHTML=cards([['Patients',d.cohorts.total_patients,'Loaded records'],['Quality flags',d.quality.findings_count,'Review audit'],['Network edges',d.network.edge_count,'At '+d.network.threshold+'%'],['Cohorts',d.cohorts.cohorts.length,'Observed labels']])+'<div class="feature-grid">'+Object.keys(d.domain_summary).map(function(key){var x=d.domain_summary[key];return '<article class="feature-card"><b>'+esc(x.label)+'</b><div class="metric"><span>Mean</span><b>'+esc(x.mean)+'</b></div><div class="metric"><span>Range</span><b>'+esc(x.min)+' – '+esc(x.max)+'</b></div></article>'}).join('')+'</div>'}
  }
  var urls={quality:'/api/research/quality',cohorts:'/api/research/cohorts',centrality:'/api/research/centrality?threshold=85',trends:'/api/research/trends',overview:'/api/research/overview?threshold=85',correlations:'/api/research/correlations',distributions:'/api/research/distributions',outliers:'/api/research/outliers'};
  panel.querySelectorAll('[data-psn-action]').forEach(function(b){b.addEventListener('click',async function(){var kind=b.dataset.psnAction;b.disabled=true;status.textContent='Loading '+kind+'…';try{var url=kind==='compare'?'/api/research/compare?patient_ids='+encodeURIComponent(panel.querySelector('#psnCompareIds').value):urls[kind];if(kind==='csvpreview'&&!panel.querySelector('#psnCsvText').value.trim())throw Error('Paste CSV text to validate.');if(kind==='compare'&&!panel.querySelector('#psnCompareIds').value.trim())throw Error('Enter at least two patient IDs, separated by commas.');var r=kind==='csvpreview'?await fetch('/api/research/csv-preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csv_text:panel.querySelector('#psnCsvText').value})}):await fetch(url,{cache:'no-store'}),d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');render(d,kind);status.textContent='Results refreshed. Descriptive only, not clinical advice.'}catch(e){status.textContent='Could not load results: '+e.message;out.textContent='Please check the API and try again.'}finally{b.disabled=false}})});
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();window.addEventListener('load',mount);
})();
</script>
"""



# ---------- Research Toolkit v2: exploration, distribution and import preview ----------

def filtered_patients(patients, q=None, diagnosis=None, min_age=None, max_age=None,
                      min_mmse=None, max_mmse=None, sort_by="patient_code",
                      order="asc", limit=50, offset=0):
    """Filter and paginate in-memory records without changing the existing patient API."""
    if limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200.")
    if offset < 0:
        raise ValueError("offset cannot be negative.")
    if order not in ("asc", "desc"):
        raise ValueError("order must be asc or desc.")
    allowed_sort = {"id", "patient_code", "age", "diagnosis", "mmse", "moca", "visit_date"}
    if sort_by not in allowed_sort:
        raise ValueError("Unsupported sort field.")
    if min_age is not None and max_age is not None and min_age > max_age:
        raise ValueError("min_age cannot exceed max_age.")
    if min_mmse is not None and max_mmse is not None and min_mmse > max_mmse:
        raise ValueError("min_mmse cannot exceed max_mmse.")
    query = (q or "").strip().casefold()
    selected = []
    for patient in patients:
        code = str(patient.get("patient_code") or "")
        if query and query not in code.casefold() and query not in str(patient.get("id", "")):
            continue
        if diagnosis and diagnosis not in ("All", "all") and patient.get("diagnosis") != diagnosis:
            continue
        age = patient.get("age")
        mmse = patient.get("mmse")
        if min_age is not None and (not finite_number(age) or float(age) < min_age):
            continue
        if max_age is not None and (not finite_number(age) or float(age) > max_age):
            continue
        if min_mmse is not None and (not finite_number(mmse) or float(mmse) < min_mmse):
            continue
        if max_mmse is not None and (not finite_number(mmse) or float(mmse) > max_mmse):
            continue
        selected.append(patient)
    def sort_key(p):
        value = p.get(sort_by)
        if finite_number(value):
            return (0, float(value), str(p.get("patient_code") or ""))
        return (1, str(value or "").casefold(), str(p.get("patient_code") or ""))
    selected.sort(key=sort_key, reverse=order == "desc")
    total = len(selected)
    return {"total": total, "limit": limit, "offset": offset,
            "has_more": offset + limit < total,
            "patients": selected[offset:offset + limit]}


def pearson_correlation(left, right):
    """Return Pearson r or None when there are too few or constant observations."""
    pairs = [(float(a), float(b)) for a, b in zip(left, right)
             if finite_number(a) and finite_number(b)]
    if len(pairs) < 2:
        return None
    xs, ys = [p[0] for p in pairs], [p[1] for p in pairs]
    mx, my = mean(xs), mean(ys)
    numerator = sum((x - mx) * (y - my) for x, y in pairs)
    denominator = math.sqrt(sum((x - mx) ** 2 for x in xs) *
                            sum((y - my) ** 2 for y in ys))
    if denominator == 0:
        return None
    return round(max(-1.0, min(1.0, numerator / denominator)), 4)


def cognitive_correlations(patients, domains):
    """Pairwise correlations with per-cell sample counts for transparent missing data."""
    matrix, counts = {}, {}
    for left in domains:
        matrix[left], counts[left] = {}, {}
        for right in domains:
            pairs = [(p.get(left), p.get(right)) for p in patients]
            valid = [(a, b) for a, b in pairs if finite_number(a) and finite_number(b)]
            matrix[left][right] = pearson_correlation(
                [p[0] for p in valid], [p[1] for p in valid])
            counts[left][right] = len(valid)
    return {"domains": list(domains), "matrix": matrix, "sample_counts": counts,
            "interpretation": "Correlation describes association in these records; it does not establish causation.",
            "disclaimer": DISCLAIMER}


def domain_distributions(patients, domains, bin_width=20):
    if bin_width not in (10, 20, 25, 50):
        raise ValueError("bin_width must be one of 10, 20, 25 or 50.")
    result = {}
    for domain in domains:
        values = [float(p[domain]) for p in patients
                  if finite_number(p.get(domain)) and 0 <= float(p[domain]) <= 100]
        bins = []
        start = 0
        while start < 100:
            end = min(100, start + bin_width)
            bins.append({"range": f"{start}-{end}", "lower": start, "upper": end,
                         "count": sum(start <= value < end or
                                      (end == 100 and value == 100) for value in values)})
            start = end
        result[domain] = {"label": DOMAIN_LABELS.get(domain, domain.title()),
                          "count": len(values), "mean": average(values),
                          "bins": bins}
    return {"bin_width": bin_width, "domains": result, "disclaimer": DISCLAIMER}


def iqr_outliers(patients, domains, minimum_group_size=4):
    """Flag statistical extremes with the 1.5-IQR rule; never label them as clinical abnormalities."""
    findings = []
    skipped = []
    for domain in domains:
        values = sorted(float(p[domain]) for p in patients
                        if finite_number(p.get(domain)))
        if len(values) < minimum_group_size:
            skipped.append({"domain": domain, "valid_count": len(values),
                            "reason": "Not enough valid observations for a stable IQR screen."})
            continue
        q1 = _percentile(values, .25)
        q3 = _percentile(values, .75)
        spread = q3 - q1
        lower, upper = q1 - 1.5 * spread, q3 + 1.5 * spread
        for patient in patients:
            value = patient.get(domain)
            if not finite_number(value):
                continue
            number = float(value)
            if number < lower or number > upper:
                findings.append({"patient_id": patient.get("id"),
                                 "patient_code": patient.get("patient_code"),
                                 "diagnosis": patient.get("diagnosis"),
                                 "domain": domain,
                                 "value": number,
                                 "lower_fence": round(lower, 2),
                                 "upper_fence": round(upper, 2),
                                 "direction": "low" if number < lower else "high"})
    return {"method": "1.5 times interquartile range",
            "outlier_count": len(findings), "findings": findings[:500],
            "findings_truncated": len(findings) > 500, "skipped_domains": skipped,
            "disclaimer": "Statistical flags require human review and are not clinical findings."}


def _percentile(sorted_values, fraction):
    if not sorted_values:
        return None
    position = (len(sorted_values) - 1) * fraction
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return sorted_values[lower]
    return sorted_values[lower] * (upper - position) + sorted_values[upper] * (position - lower)


def shortest_similarity_path(patients, similarity_fn, source_id, target_id, threshold=85):
    """Breadth-first shortest path on edges meeting the requested similarity threshold."""
    if not 0 <= threshold <= 100:
        raise ValueError("threshold must be between 0 and 100.")
    by_id = {p.get("id"): p for p in patients if p.get("id") is not None}
    if source_id not in by_id or target_id not in by_id:
        raise LookupError("Source or target patient ID was not found.")
    if source_id == target_id:
        return {"found": True, "path": [source_id], "hops": 0,
                "threshold": threshold, "connections": [],
                "disclaimer": "A graph path reflects this thresholded demo similarity graph."}
    adjacency = {pid: [] for pid in by_id}
    for i, left in enumerate(patients):
        left_id = left.get("id")
        if left_id not in adjacency:
            continue
        for right in patients[i + 1:]:
            right_id = right.get("id")
            if right_id not in adjacency:
                continue
            score = float(similarity_fn(left, right))
            if score >= threshold:
                adjacency[left_id].append((right_id, round(score, 1)))
                adjacency[right_id].append((left_id, round(score, 1)))
    queue = deque([source_id])
    previous = {source_id: None}
    via = {}
    while queue:
        current = queue.popleft()
        for neighbor, score in adjacency[current]:
            if neighbor in previous:
                continue
            previous[neighbor] = current
            via[neighbor] = score
            if neighbor == target_id:
                queue.clear()
                break
            queue.append(neighbor)
    if target_id not in previous:
        return {"found": False, "path": [], "hops": None, "threshold": threshold,
                "connections": [], "disclaimer": "No path was found at this threshold."}
    path = []
    current = target_id
    while current is not None:
        path.append(current)
        current = previous[current]
    path.reverse()
    connections = [{"source": path[i], "target": path[i + 1],
                    "similarity": via[path[i + 1]]}
                   for i in range(len(path) - 1)]
    return {"found": True, "path": path, "hops": len(path) - 1,
            "threshold": threshold, "connections": connections,
            "disclaimer": "A graph path reflects this thresholded demo similarity graph."}


def preview_csv_import(csv_text, domains, max_rows=500):
    """Validate a CSV import without inserting or updating any database rows."""
    if not isinstance(csv_text, str) or not csv_text.strip():
        raise ValueError("CSV content is empty.")
    if len(csv_text) > 1_000_000:
        raise ValueError("CSV preview is limited to 1 MB.")
    reader = csv.DictReader(io.StringIO(csv_text))
    headers = [str(h or "").strip() for h in (reader.fieldnames or [])]
    required = ["patient_code", "age", "sex", "diagnosis", "mmse", "moca", *domains]
    missing_headers = [field for field in required if field not in headers]
    duplicate_headers = sorted({h for h in headers if headers.count(h) > 1})
    findings = []
    if missing_headers:
        findings.append({"row": None, "severity": "error", "type": "missing_headers",
                         "fields": missing_headers, "message": "Required CSV columns are missing."})
    if duplicate_headers:
        findings.append({"row": None, "severity": "error", "type": "duplicate_headers",
                         "fields": duplicate_headers, "message": "CSV column names must be unique."})
    seen_codes = set()
    preview_rows = []
    row_count = 0
    for row_number, row in enumerate(reader, start=2):
        row_count += 1
        if row_count > max_rows:
            findings.append({"row": row_number, "severity": "error", "type": "row_limit",
                             "fields": [], "message": f"CSV preview is limited to {max_rows} data rows."})
            break
        clean = {str(k).strip(): (v.strip() if isinstance(v, str) else v)
                 for k, v in row.items() if k is not None}
        code = str(clean.get("patient_code") or "").strip()
        row_errors = []
        if not code:
            row_errors.append(("patient_code", "Patient code is required."))
        elif code.casefold() in seen_codes:
            row_errors.append(("patient_code", "Patient code is duplicated in this CSV."))
        seen_codes.add(code.casefold()) if code else None
        for field, low, high in [("age", 18, 120), ("mmse", 0, 30), ("moca", 0, 30),
                                 *((d, 0, 100) for d in domains)]:
            value = clean.get(field)
            if value in (None, ""):
                row_errors.append((field, "Value is required."))
            elif not finite_number(value) or not low <= float(value) <= high:
                row_errors.append((field, f"Value must be numeric and within {low} to {high}."))
            else:
                clean[field] = float(value) if field not in ("age",) else int(float(value))
        for field in ("sex", "diagnosis"):
            if not clean.get(field):
                row_errors.append((field, "Value is required."))
        for field, message in row_errors:
            findings.append({"row": row_number, "severity": "error", "type": "invalid_value",
                             "fields": [field], "message": message})
        preview_rows.append({"row": row_number, "patient_code": code,
                             "valid": not row_errors, "values": clean})
    valid_rows = sum(1 for row in preview_rows if row["valid"])
    return {"row_count": len(preview_rows), "valid_rows": valid_rows,
            "invalid_rows": len(preview_rows) - valid_rows,
            "missing_headers": missing_headers, "duplicate_headers": duplicate_headers,
            "can_import": not findings and valid_rows > 0,
            "findings_count": len(findings), "findings": findings[:500],
            "findings_truncated": len(findings) > 500, "preview": preview_rows[:20],
            "note": "Preview only. This endpoint does not write records to the database."}


def export_patients_csv(patients, domains):
    fields = ["id", "patient_code", "age", "sex", "diagnosis", "mmse", "moca",
              "visit", "visit_date", *domains]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for patient in patients:
        writer.writerow({field: patient.get(field) for field in fields})
    return stream.getvalue()


def add_v2_routes(router, all_patients, similarity_fn, domains):
    """Register additive, read-only routes. Existing endpoints remain untouched."""
    from pydantic import BaseModel, Field

    class CSVPreviewRequest(BaseModel):
        csv_text: str = Field(min_length=1, max_length=1_000_000)

    @router.get("/api/research/patients")
    def research_patient_search(q: str | None = None, diagnosis: str | None = None,
                                min_age: int | None = None, max_age: int | None = None,
                                min_mmse: float | None = None, max_mmse: float | None = None,
                                sort_by: str = "patient_code", order: str = "asc",
                                limit: int = 50, offset: int = 0):
        try:
            return filtered_patients(all_patients(), q, diagnosis, min_age, max_age,
                                     min_mmse, max_mmse, sort_by, order, limit, offset)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/api/research/correlations")
    def research_correlations():
        return cognitive_correlations(all_patients(), domains)

    @router.get("/api/research/distributions")
    def research_distributions(bin_width: int = 20):
        try:
            return domain_distributions(all_patients(), domains, bin_width)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/api/research/outliers")
    def research_outliers():
        return iqr_outliers(all_patients(), domains)

    @router.get("/api/research/path")
    def research_path(source_id: int, target_id: int, threshold: float = 85):
        try:
            return shortest_similarity_path(all_patients(), similarity_fn,
                                            source_id, target_id, threshold)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except LookupError as exc:
            raise HTTPException(404, str(exc))

    @router.get("/api/research/export.csv")
    def research_csv_export(q: str | None = None, diagnosis: str | None = None):
        result = filtered_patients(all_patients(), q=q, diagnosis=diagnosis,
                                   limit=200, offset=0)
        data = export_patients_csv(result["patients"], domains)
        return Response(data, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="psn-filtered-patients.csv"'})

    @router.post("/api/research/csv-preview")
    def research_csv_preview(payload: CSVPreviewRequest):
        try:
            return preview_csv_import(payload.csv_text, domains)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return router
