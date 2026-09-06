import os,re

EXTS={'.py','.java','.js','.ts','.go','.c','.cc','.cpp','.h','.hpp','.cs','.kt','.kts','.rs','.rb','.php','.swift','.yaml','.yml','.json','.xml','.properties','.conf','.cfg','.ini','.toml','.md','.txt','.pem','.cnf'}
RULES=[
('rsa1024',r'RSA\.generate\s*\(\s*1024|rsa\.key\.size\s*[=:]\s*["\']?1024|1024.{0,30}RSA','RSA-1024',True,.99,'urgent'),
('rsa',r'RSA\.generate\s*\(|Crypto\.PublicKey\.RSA|from\s+Crypto\.PublicKey\s+import\s+RSA|RSA/','RSA',True,.92,'medium'),
('ecc',r'ec\.generate_private_key|ECDSA\(|SECP(?:256|384|521)','ECC/ECDSA',True,.92,'medium'),
('md5',r'\bMD5\b|hashlib\.md5\s*\(|createHash\s*\(\s*["\']md5["\']','MD5',False,.98,'urgent'),
('sha1',r'\bSHA[-_ ]?1\b|hashlib\.sha1\s*\(|SHA1\.new\s*\(|sha1WithRSAEncryption','SHA-1',False,.97,'urgent'),
('des',r'\bDES\b|DES\.new\s*\(|DES/ECB|DES/CBC','DES',False,.97,'urgent'),
('3des',r'3DES|DES3|DESede|tripledes|des-ede','3DES',False,.97,'urgent'),
('aescbc',r'AES(?:[-_/ ]?(?:128|192|256)[-_ ]?CBC)|AES\.MODE_CBC|AES/CBC','AES-CBC',False,.94,'medium'),
('pkcs1',r'PKCS1Padding|PKCS#?1|pkcs1_v1_5','RSA-PKCS#1 v1.5',True,.93,'medium'),
('tls10',r'TLSv?1\.0|TLSv?1_0|TLS 1\.0','TLS 1.0',False,.99,'urgent'),
('tls11',r'TLSv?1\.1|TLSv?1_1|TLS 1\.1','TLS 1.1',False,.99,'urgent'),
('weak-random',r'Math\.random\s*\(|random\.random\s*\(','Weak randomness',False,.88,'medium'),
('modern',r'AES-256-GCM|AES\.GCM|SHA-256|sha256|RSA-2048|RSA-3072|ML-KEM|ML-DSA|SLH-DSA','Modern/PQC crypto',False,.82,'low'),
]

def criticality(path):
 p=path.lower();
 if any(x in p for x in ('payment','auth','login','token','key','cert','kms','ca','gateway')): return 'high'
 if any(x in p for x in ('report','document','notification','legacy','order')): return 'medium'
 return 'low'

def system_name(root,path):
 rel=os.path.relpath(path,root).replace('\\','/'); parts=rel.split('/')
 return parts[0] if len(parts)>1 else os.path.basename(root) or 'application'

def scan_file(root,path):
 out=[]
 try: lines=open(path,'r',encoding='utf-8',errors='ignore').read().splitlines()
 except OSError: return out
 for ln,text in enumerate(lines,1):
  matches=[]
  for rid,pat,alg,qv,conf,risk in RULES:
   if re.search(pat,text,re.I): matches.append((rid,alg,qv,conf,risk))
  # avoid noisy generic duplicates; retain most specific/highest risk per line
  seen=set()
  for rid,alg,qv,conf,risk in sorted(matches,key=lambda x:(x[4]!='urgent',x[1])):
   if alg in seen: continue
   seen.add(alg)
   if text.strip().startswith(('#','//')) or 'test' in os.path.basename(path).lower(): conf=round(conf*.45,2)
   out.append({'system':system_name(root,path),'file':path,'line':ln,'code_snippet':text.strip()[:180],'rule_id':rid,'algorithm':alg,'quantum_vulnerable':qv,'confidence':conf,'business_criticality':criticality(path),'base_risk':risk})
 return out

def scan(root):
 findings=[]
 if not os.path.isdir(root): return findings
 for dp,dirs,files in os.walk(root):
  dirs[:]=[d for d in dirs if d not in {'.git','.venv','node_modules','__pycache__','_uploaded_scans'}]
  for fn in files:
   if os.path.splitext(fn)[1].lower() in EXTS: findings += scan_file(root,os.path.join(dp,fn))
 return findings
