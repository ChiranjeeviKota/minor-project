import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, adjusted_rand_score
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

DOMAINS = ["memory", "attention", "executive", "language", "visuospatial", "processing_speed", "orientation"]
WEIGHTS = np.array([.22, .14, .18, .12, .12, .10, .12])
def vec(p): return np.array([float(getattr(p, d)) for d in DOMAINS])
def weighted(a,b): return float(max(0, 100 - np.sum(WEIGHTS * np.abs(vec(a)-vec(b)))))
def cosine(a,b):
    x,y=vec(a),vec(b); den=np.linalg.norm(x)*np.linalg.norm(y)
    return float(((np.dot(x,y)/den)+1)*50) if den else 0.0
def euclidean(a,b): return float(100/(1+np.linalg.norm(vec(a)-vec(b))/10))
def graph_features(p):
    x=vec(p); s=1-np.abs(x[:,None]-x[None,:])/100
    np.fill_diagonal(s,0); strength=s.sum(axis=1)
    return {"mean_strength":float(strength.mean()),"density":float((s>0).sum()/(len(x)*(len(x)-1))),"mean_centrality":float((strength/(len(x)-1)).mean()),"variance":float(x.var())}
def graph_similarity(a,b):
    fa,fb=graph_features(a),graph_features(b)
    x=np.array(list(fa.values())); y=np.array(list(fb.values()))
    return float(100/(1+np.linalg.norm((x-y)/np.array([6,1,1,100]))))
def combined(a,b): return .55*weighted(a,b)+.45*graph_similarity(a,b)
def similarity(a,b,method):
    return {"weighted":weighted,"cosine":cosine,"euclidean":euclidean,"graph":graph_similarity,"combined":combined}.get(method,combined)(a,b)
def cognitive_network(p):
    x=vec(p); edges=[]
    for i in range(len(DOMAINS)):
        for j in range(i+1,len(DOMAINS)):
            edges.append({"source":DOMAINS[i],"target":DOMAINS[j],"weight":round(float(100-abs(x[i]-x[j])),2)})
    return {"nodes":[{"id":d,"value":float(getattr(p,d))} for d in DOMAINS],"edges":edges}
def clusters(ps,k=3):
    if len(ps)<k+1: return {"clusters":[],"silhouette":None,"ari":None}
    X=np.array([vec(p) for p in ps]); labels=KMeans(n_clusters=k,n_init=10,random_state=42).fit_predict(X)
    truth=[{"Healthy":0,"MCI":1,"Alzheimer's":2}.get(p.diagnosis,-1) for p in ps]
    return {"clusters":[{"patient_id":p.id,"cluster":int(c)} for p,c in zip(ps,labels)],"silhouette":float(silhouette_score(X,labels)),"ari":float(adjusted_rand_score(truth,labels))}
def ml(ps):
    X=np.array([vec(p) for p in ps]); y=np.array([{"Healthy":0,"MCI":1,"Alzheimer's":2}.get(p.diagnosis,0) for p in ps])
    xt,xv,yt,yv=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    m=LogisticRegression(max_iter=1000).fit(xt,yt); pred=m.predict(xv)
    out={"accuracy":float(accuracy_score(yv,pred)),"precision":float(precision_score(yv,pred,average="weighted",zero_division=0)),"recall":float(recall_score(yv,pred,average="weighted",zero_division=0)),"f1":float(f1_score(yv,pred,average="weighted",zero_division=0))}
    try: out["roc_auc"]=float(roc_auc_score(yv,m.predict_proba(xv),multi_class="ovr"))
    except Exception: out["roc_auc"]=None
    out["feature_importance"]=[{"feature":d,"importance":float(np.mean(np.abs(m.coef_[:,i])))} for i,d in enumerate(DOMAINS)]
    return out
