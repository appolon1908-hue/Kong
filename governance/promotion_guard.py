#!/usr/bin/env python3
import fnmatch,json,os,pathlib,sys
p=json.loads(pathlib.Path("governance/promotion-policy.json").read_text())
head=os.environ.get("GITHUB_HEAD_REF",""); base=os.environ.get("GITHUB_BASE_REF","")
b=p["bootstrap_exception"]
if head==b["head"] and base==b["base"]: print("PROMOTION_OK bootstrap"); raise SystemExit(0)
ok=False
for r in p["accepted_promotions"]:
    if fnmatch.fnmatch(head,r["head"]) and fnmatch.fnmatch(base,r["base"]):
        ok=True
        if r.get("relation")=="matching-section-required":
            ok=head[len("subsection/"):].split("--",1)[0]==base[len("section/"):]
        if ok: break
print(("PROMOTION_OK" if ok else "PROMOTION_BLOCKED")+f" head={head} base={base}")
raise SystemExit(0 if ok else 1)
