def enrich_with_recommendations(findings):
 for f in findings:
  a=f['algorithm'].lower()
  if 'rsa' in a or 'ecc' in a:
   target='ML-KEM-768 + ML-DSA' if 'pkcs' not in a else 'ML-DSA + modern TLS policy'; why='Public-key cryptography is exposed to Shor-style quantum attacks; use an approved PQC/hybrid path and validate interoperability.'; effort='HIGH' if f.get('business_criticality')=='high' else 'MODERATE'; priority='P0' if f.get('base_risk')=='urgent' else 'P1'
  elif 'sha' in a or 'md5' in a:
   target='SHA-256 / SHA-3'; why='Legacy digest primitives weaken integrity assurance and should be replaced with modern approved hashes.'; effort='LOW'; priority='P1'
  elif 'des' in a or '3des' in a:
   target='AES-256-GCM'; why='Legacy DES-family encryption should be retired in favor of authenticated modern encryption.'; effort='MODERATE'; priority='P0'
  elif 'tls 1' in a:
   target='TLS 1.2+ / TLS 1.3'; why='Legacy TLS versions expand protocol exposure and should be disabled in favor of current policy.'; effort='MODERATE'; priority='P0'
  elif 'cbc' in a:
   target='AES-GCM / ChaCha20-Poly1305'; why='Authenticated encryption reduces padding/oracle and integrity risks associated with legacy CBC usage.'; effort='MODERATE'; priority='P1'
  elif 'random' in a:
   target='OS CSPRNG / platform crypto API'; why='Predictable randomness can undermine keys, tokens and nonces.'; effort='LOW'; priority='P1'
  else:
   target='Keep modern primitive + crypto-agility monitoring'; why='No immediate legacy signal was detected; retain under inventory and policy monitoring.'; effort='LOW'; priority='P3'
  f['recommendation']=f"{target}. {why}"
  f['recommendation_detail']={'target':target,'why':why,'effort':effort,'priority':priority}
  m=f.get('mosca',{}); verdict=m.get('verdict','low'); f['why']={'category':m.get('classification',verdict.upper()),'reason':('The rule detected a known legacy/quantum-vulnerable pattern and its X + Y exposure is outside or close to the selected Z horizon.' if verdict in ('urgent','medium') else 'The detected primitive remains within the selected planning horizon and has lower migration pressure.')}
 return findings
