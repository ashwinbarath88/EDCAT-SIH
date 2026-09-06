DEFAULT_Z=12

def score_findings(findings,quantum_threat_years=DEFAULT_Z):
 z=float(quantum_threat_years or DEFAULT_Z)
 out=[]
 for f in findings:
  crit={'high':7,'medium':4,'low':2}.get(f.get('business_criticality'),2)
  migration={'urgent':6,'medium':3,'low':1}.get(f.get('base_risk','low'),1)
  x=crit; y=migration; margin=round(z-(x+y),1)
  pct=round(((x+y)/max(z,1))*100)
  if f['base_risk']=='urgent' or pct>100: verdict='urgent'
  elif pct>=70: verdict='medium'
  else: verdict='low'
  reason=(f"X + Y = {x + y} years exceeds Z = {z:g} years, leaving no planning margin." if verdict=='urgent' else
          f"X + Y = {x + y} years approaches Z = {z:g} years; migration margin is limited." if verdict=='medium' else
          f"X + Y = {x + y} years remains inside Z = {z:g} years with planning margin.")
  nf=dict(f); nf['mosca']={'x_years':x,'y_years':y,'z_years':z,'exposure_window_years':x+y,'margin_years':margin,'percentage':pct,'verdict':verdict,'classification':{'urgent':'URGENT','medium':'AT-RISK','low':'WITHIN HORIZON'}[verdict],'reason':reason,'quantum_threat_years':z}; out.append(nf)
 return out
