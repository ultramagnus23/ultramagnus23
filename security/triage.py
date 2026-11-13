#!/usr/bin/env python3
"""Build a deduplicated remediation queue from Gitleaks, Semgrep, Trivy, OSV, npm audit and Ruff."""
import argparse,csv,hashlib,json,re
from collections import Counter,defaultdict
from pathlib import Path
SEV={"CRITICAL":5,"HIGH":4,"MODERATE":3,"MEDIUM":3,"LOW":2,"INFO":1,"UNKNOWN":0}
def load(p):
 try:return json.loads(p.read_text(encoding="utf-8"))
 except (OSError,ValueError):return None
def pathnorm(s):
 s=(s or "").replace("\\","/")
 for m in ("/home/runner/work/","/src/"):
  if m in s:s=s.split(m,1)[1]
 return s.lstrip("/")
def cvss(s):
 try:n=float(s)
 except (TypeError,ValueError):return "UNKNOWN"
 return "CRITICAL" if n>=9 else "HIGH" if n>=7 else "MODERATE" if n>=4 else "LOW"
def rank(kind,sev):
 n=SEV.get((sev or "UNKNOWN").upper(),0)
 if kind=="secret":return "P0-VERIFY",95
 if kind=="dependency":return ("P0-CRITICAL",90) if n>=5 else ("P1-HIGH",80) if n==4 else ("P2-MEDIUM",60) if n==3 else ("P3-LOW",40)
 if kind=="security-code":return "P1-REVIEW",75
 return "P4-QUALITY",10
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--input-dir",required=True);ap.add_argument("--out-dir",required=True);a=ap.parse_args()
 root,out=Path(a.input_dir),Path(a.out_dir);out.mkdir(parents=True,exist_ok=True)
 rows,aliases={},{}
 def add(key,r):
  if key not in rows:rows[key]=r
  else:
   old=rows[key];old["sources"]=sorted(set(old["sources"]+r["sources"]));old["evidence"]=list(dict.fromkeys(old["evidence"]+r["evidence"]))[:8]
   if SEV.get(r["severity"],0)>SEV.get(old["severity"],0):old["severity"]=r["severity"]
   for k in ("fixed_version","url"):
    if r.get(k):old[k]=r[k]
 def emit(repo,key,kind,sev,title,**kw):
  p,score=rank(kind,sev)
  r=dict(id=hashlib.sha1(key.encode()).hexdigest()[:12],repository=repo,kind=kind,priority=p,priority_score=score,severity=sev,title=(title or "untitled")[:260],package="",ecosystem="",installed_version="",fixed_version="",advisory_id="",file="",line="",rule_id="",sources=[],url="",evidence=[],status="needs-validation",exploitability="not-assessed",notes="Validate current source, dependency path and runtime reachability before changing code.")
  r.update(kw);add(key,r)
 for rd in sorted(x for x in root.iterdir() if x.is_dir()):
  repo=rd.name;d=load(rd/"osv.json")
  if d:
   for result in d.get("results",[]):
    lock=pathnorm(result.get("source",{}).get("path",""))
    for pr in result.get("packages",[]):
     pkg=pr.get("package",{});name=pkg.get("name","");eco=pkg.get("ecosystem","")
     for v in pr.get("vulnerabilities",[]):
      aid=v.get("id") or "OSV-UNKNOWN";als=set(v.get("aliases",[])+[aid])
      score=max([float(g.get("max_severity",0) or 0) for g in pr.get("groups",[]) if g.get("max_severity")],default=0)
      sev=(v.get("database_specific",{}).get("severity") or cvss(score)).upper()
      fixed=[]
      for af in v.get("affected",[]):
       for rg in af.get("ranges",[]):
        fixed += [e["fixed"] for e in rg.get("events",[]) if "fixed" in e]
      key="DEP|"+repo+"|"+eco+"|"+name+"|"+aid
      emit(repo,key,"dependency",sev,v.get("summary") or name+" advisory",package=name,ecosystem=eco,installed_version=pkg.get("version",""),fixed_version=", ".join(dict.fromkeys(fixed)),advisory_id=aid,file=lock,sources=["OSV"],url=next((x.get("url") for x in v.get("references",[]) if x.get("url")),""),evidence=[v.get("details","")[:350]] if v.get("details") else [],notes="Check whether affected version is shipped/reachable; upgrade to compatible fixed version.")
      for alias in als:aliases[(repo,name,alias)]=key
  for fn,tool in (("gitleaks.sarif","Gitleaks"),("semgrep.sarif","Semgrep"),("trivy.sarif","Trivy")):
   sar=load(rd/fn)
   if not sar:continue
   for run in sar.get("runs",[]):
    for x in run.get("results",[]):
     loc=(x.get("locations") or [{}])[0].get("physicalLocation",{});file=pathnorm(loc.get("artifactLocation",{}).get("uri",""));line=loc.get("region",{}).get("startLine","");rule=x.get("ruleId","unknown");msg=(x.get("message") or {}).get("text","")
     if tool=="Trivy" and re.match(r"(CVE|GHSA)-",rule):
      m=re.search(r"Package:\s*(.+)",msg);name=m.group(1).strip() if m else "";s=re.search(r"Severity:\s*(\w+)",msg,re.I);f=re.search(r"Fixed Version:\s*([^\n]+)",msg,re.I)
      key=aliases.get((repo,name,rule),"DEP|"+repo+"|trivy|"+name+"|"+rule)
      emit(repo,key,"dependency",s.group(1).upper() if s else "UNKNOWN",name+" "+rule,package=name,advisory_id=rule,file=file,line=line,fixed_version=f.group(1).strip() if f else "",sources=["Trivy"],evidence=[msg[:400]],notes="Correlate with OSV/npm; scanners can report the same advisory.")
      continue
     if tool=="Gitleaks":kind,sev="secret","HIGH"
     else:
      sev="HIGH" if x.get("level")=="error" else "MODERATE" if x.get("level")=="warning" else "LOW";hay=(rule+" "+msg).lower()
      kind="security-code" if any(t in hay for t in ("security","sql","secret","traversal","ssrf","urllib","pickle","dangerouslysetinnerhtml","websocket","child-process","integrity","csrf","taint")) else "quality"
     fp=(x.get("fingerprints") or {}).get("matchBasedId/v1") or (x.get("partialFingerprints") or {}).get("primaryLocationLineHash") or f"{rule}|{file}|{line}"
     emit(repo,"SARIF|"+repo+"|"+tool+"|"+fp,kind,sev,msg.splitlines()[0] or rule,file=file,line=line,rule_id=rule,sources=[tool],evidence=[msg[:500]],notes="Review source context/data flow; scanner output does not prove exploitability.")
  for p in rd.glob("npm-audit*.json"):
   d=load(p)
   if not d:continue
   for name,v in d.get("vulnerabilities",{}).items():
    for via in v.get("via",[]):
     if not isinstance(via,dict):continue
     url=via.get("url","");aid=url.rsplit("/",1)[-1] if url else str(via.get("source") or via.get("title") or "npm-advisory")
     key=aliases.get((repo,name,aid),"DEP|"+repo+"|npm|"+name+"|"+aid)
     emit(repo,key,"dependency",(via.get("severity") or v.get("severity") or "UNKNOWN").upper(),via.get("title") or name+" npm advisory",package=name,ecosystem="npm",advisory_id=aid,file=";".join(v.get("nodes",[])[:3]),sources=["npm audit"],url=url,evidence=[via.get("range","")],notes="Confirm dependency path and patched compatible release.")
  d=load(rd/"ruff.json")
  if isinstance(d,list):
   for x in d:
    file=pathnorm(x.get("filename",""));code=x.get("code","");key="RUFF|"+repo+"|"+file+"|"+code
    emit(repo,key,"quality","LOW","Ruff "+code+": "+x.get("message",""),ecosystem="python",file=file,line=(x.get("location") or {}).get("row",""),rule_id=code,sources=["Ruff"],url=x.get("url",""),evidence=[x.get("message","")],notes="Keep lint cleanup separate from security remediation.")
 data=sorted(rows.values(),key=lambda r:(-r["priority_score"],r["repository"],r["file"],str(r["line"]),r["id"]))
 (out/"findings.json").write_text(json.dumps({"schema_version":1,"finding_count":len(data),"findings":data},indent=2),encoding="utf-8")
 cols=["id","repository","priority","severity","kind","title","package","ecosystem","installed_version","fixed_version","advisory_id","file","line","rule_id","sources","status","exploitability","url","notes"]
 with (out/"findings.csv").open("w",newline="",encoding="utf-8") as f:
  w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
  for r in data:w.writerow({k:";".join(r[k]) if isinstance(r.get(k),list) else r.get(k,"") for k in cols})
 counts=Counter(r["priority"] for r in data);byrepo=defaultdict(Counter)
 for r in data:byrepo[r["repository"]][r["priority"]]+=1
 md=["# Deduplicated remediation queue","",f"**{len(data)} normalized records across {len(byrepo)} repositories.** All findings require validation; severity does not prove exploitability.","","## Priority counts","","| Priority | Count |","|---|---:|"]
 for p in ("P0-VERIFY","P0-CRITICAL","P1-HIGH","P1-REVIEW","P2-MEDIUM","P3-LOW","P4-QUALITY"):
  if counts[p]:md.append(f"| {p} | {counts[p]} |")
 md+=["","## Repository backlog","","| Repository | Verify | Critical | High/review | Medium | Low | Quality |","|---|---:|---:|---:|---:|---:|---:|"]
 for repo,c in sorted(byrepo.items(),key=lambda x:(-sum(x[1][p] for p in ("P0-VERIFY","P0-CRITICAL","P1-HIGH","P1-REVIEW")),x[0])):
  md.append(f"| {repo} | {c['P0-VERIFY']} | {c['P0-CRITICAL']} | {c['P1-HIGH']+c['P1-REVIEW']} | {c['P2-MEDIUM']} | {c['P3-LOW']} | {c['P4-QUALITY']} |")
 md+=["","## Top 100 non-quality findings","","| Priority | Repo | Severity | Finding | File | Sources |","|---|---|---|---|---|---|"]
 for r in [x for x in data if x["kind"]!="quality"][:100]:md.append(f"| {r['priority']} | {r['repository']} | {r['severity']} | {r['title'][:100].replace('|','/')} | {r['file'][:55]} | {', '.join(r['sources'])} |")
 md+=["","## Remediation loop","","1. Validate on the current default branch and identify runtime reachability.","2. Make one coherent fix on a dedicated branch.","3. Run tests, build, security regression tests and scanners.","4. Confirm the finding disappears and no regressions appear.","5. Open a PR with evidence, rollback plan and residual risk.","6. Merge only after CI and human review.","","## Caveats","","- P0-VERIFY is a Gitleaks hit requiring human confirmation, not a confirmed credential.","- Dependency advisories are merged by package/advisory where aliases match; unmatched duplicates may remain.","- Ruff is grouped by file/rule so lint noise does not dominate.","- No dependency upgrades or source edits are performed automatically."]
 (out/"findings.md").write_text("\n".join(md)+"\n",encoding="utf-8")
 print(json.dumps({"findings":len(data),"repositories":len(byrepo),"priorities":dict(counts)},indent=2))
if __name__=="__main__":main()
