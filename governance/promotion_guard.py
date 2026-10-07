#!/usr/bin/env python3
import argparse, fnmatch, json, os, pathlib, sys

p=argparse.ArgumentParser()
p.add_argument("--head")
p.add_argument("--base")
a=p.parse_args()
head=a.head or os.environ.get("GITHUB_HEAD_REF","")
base=a.base or os.environ.get("GITHUB_BASE_REF","")

policy=json.loads(pathlib.Path("governance/promotion-policy.json").read_text())
b=policy["bootstrap_exception"]
if head==b["head"] and base==b["base"]:
    print("PROMOTION_GUARD=PASS bootstrap")
    raise SystemExit(0)

ok=False
for rule in policy["accepted_promotions"]:
    if fnmatch.fnmatch(head,rule["head"]) and fnmatch.fnmatch(base,rule["base"]):
        ok=True
        if rule.get("relation")=="matching-section-required":
            if not head.startswith("subsection/") or not base.startswith("section/"):
                ok=False
            else:
                src=head[len("subsection/"):].split("--",1)[0]
                dst=base[len("section/"):]
                ok=(src==dst)
        if ok:
            break

if not ok:
    print(f"PROMOTION_GUARD=BLOCK head={head} base={base}")
    raise SystemExit(1)
print(f"PROMOTION_GUARD=PASS head={head} base={base}")
