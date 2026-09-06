import os,shutil,tempfile,zipfile
from datetime import datetime,timezone
from flask import Flask,request,jsonify,send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from scanner import scan
from mosca import score_findings,DEFAULT_Z
from recommend import enrich_with_recommendations

BASE=os.path.dirname(os.path.abspath(__file__)); FRONT=os.path.join(os.path.dirname(BASE),'frontend'); UP=os.path.join(BASE,'_uploaded_scans'); MAX=100*1024*1024
app=Flask(__name__,static_folder=FRONT,static_url_path=''); app.config['MAX_CONTENT_LENGTH']=MAX; CORS(app,resources={r'/api/*':{'origins':'*'}})
STATE={'root':os.path.join(BASE,'sample_systems'),'label':'Demo environment','last':None}

def now(): return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def risk_score(fs):
 counts={'urgent':0,'medium':0,'low':0}; alg={}; systems={}
 for f in fs:
  r=f['mosca']['verdict']; counts[r]=counts.get(r,0)+1; alg[f['algorithm']]=alg.get(f['algorithm'],0)+1
  systems[f['system']]=max(systems.get(f['system'],0),{'low':0,'medium':1,'urgent':2}[r])
 posture='Urgent' if counts['urgent'] else 'At-Risk' if counts['medium'] else 'Ready'
 return {'total_findings':len(fs),'systems_scanned':len(systems),'system_names':sorted(systems),'verdict_counts':counts,'algorithm_counts':alg,'system_risk_levels':{k:{0:'low',1:'medium',2:'urgent'}[v] for k,v in systems.items()},'posture':posture,'quantum_exposure_percent':round(counts['urgent']/len(fs)*100) if fs else 0}

def pipeline(root,z):
 fs=enrich_with_recommendations(score_findings(scan(root),z)); root=os.path.realpath(root)
 for f in fs:
  f['location_only']=f"{os.path.relpath(f['file'],root).replace(os.sep,'/')}:L{f['line']}"
 return fs

def payload(fs,z):
 s=risk_score(fs); return {'scanned_at':now(),'quantum_threat_years_used':z,'target_label':STATE['label'],'summary':s,'findings':fs}

def safe_extract(src,dst):
 root=os.path.realpath(dst)
 with zipfile.ZipFile(src) as z:
  for m in z.infolist():
   target=os.path.realpath(os.path.join(root,m.filename))
   if target!=root and not target.startswith(root+os.sep): raise ValueError('Unsafe ZIP path detected.')
  z.extractall(root)

@app.errorhandler(413)
def too_large(e): return jsonify(error='ZIP exceeds the 100 MB prototype limit.'),413
@app.route('/api/health')
def health(): return jsonify(status='online',service='ECDAT',version='6.0-wow',timestamp=now())
@app.route('/api/scan')
def demo():
 z=float(request.args.get('quantum_threat_years') or DEFAULT_Z); STATE['root']=os.path.join(BASE,'sample_systems'); STATE['label']='ECDAT Demo Environment'; fs=pipeline(STATE['root'],z); return jsonify(payload(fs,z))
@app.route('/api/scan-upload',methods=['POST'])
def upload():
 f=request.files.get('file')
 if not f or not f.filename: return jsonify(error='No file received. Choose a ZIP codebase.'),400
 name=secure_filename(f.filename)
 if not name.lower().endswith('.zip'): return jsonify(error='Please select a .zip codebase.'),400
 if os.path.isdir(UP): shutil.rmtree(UP)
 os.makedirs(UP,exist_ok=True)
 tmp=None
 try:
  fd,tmp=tempfile.mkstemp(suffix='.zip',dir=UP); os.close(fd); f.save(tmp); extract=os.path.join(UP,'source'); os.makedirs(extract,exist_ok=True); safe_extract(tmp,extract)
  entries=[e for e in os.listdir(extract) if not e.startswith('.')]
  root=extract
  if len(entries)==1 and os.path.isdir(os.path.join(extract,entries[0])): root=os.path.join(extract,entries[0])
  z=float(request.form.get('quantum_threat_years') or DEFAULT_Z); STATE['root']=root; STATE['label']=f'Uploaded · {name}'; fs=pipeline(root,z); return jsonify(payload(fs,z))
 except zipfile.BadZipFile: return jsonify(error='The selected file is not a valid ZIP.'),400
 except ValueError as e: return jsonify(error=str(e)),400
 except Exception as e: return jsonify(error=f'Upload/scan failed: {e}'),500
 finally:
  if tmp and os.path.exists(tmp): os.remove(tmp)
@app.route('/api/scan-path',methods=['POST'])
def scan_path():
 b=request.get_json(silent=True) or {}; root=os.path.abspath(os.path.expanduser(str(b.get('path','')).strip()))
 if not os.path.isdir(root): return jsonify(error='That folder does not exist on the machine running ECDAT.'),400
 z=float(b.get('quantum_threat_years') or DEFAULT_Z); STATE['root']=root; STATE['label']=f'Repository · {os.path.basename(root) or root}'; return jsonify(payload(pipeline(root,z),z))
@app.route('/api/report')
def report():
 z=float(request.args.get('quantum_threat_years') or DEFAULT_Z); fs=pipeline(STATE['root'],z); return jsonify({'bomFormat':'CycloneDX-CBOM','specVersion':'1.6-prototype','serialNumber':'urn:ecdat:'+datetime.now().strftime('%Y%m%d%H%M%S'),'metadata':{'timestamp':now(),'tool':'ECDAT','target':STATE['label'],'quantum_threat_timeline_years':z},'summary':risk_score(fs),'components':[{'type':'cryptographic-asset','system':f['system'],'location':f['location_only'],'algorithm':f['algorithm'],'quantum_vulnerable':f['quantum_vulnerable'],'confidence':f['confidence'],'business_criticality':f['business_criticality'],'risk':f['mosca'],'recommendation':f['recommendation']} for f in fs]})
@app.route('/')
def index(): return send_from_directory(FRONT,'index.html')
@app.route('/<path:p>')
def assets(p): return send_from_directory(FRONT,p)
if __name__=='__main__': app.run(host=os.environ.get('HOST','127.0.0.1'),port=int(os.environ.get('PORT','5050')),debug=False)
