#!/usr/bin/env python3
import argparse, json, pathlib, sys

p=argparse.ArgumentParser()
p.add_argument("--head",required=True)
p.add_argument("--base",required=True)
a=p.parse_args()

policy=json.loads(pathlib.Path("governance/promotion-policy.json").read_text())
head=a.head
base=a.base

b=policy["bootstrap_exception"]
if head==b["head"] and base==b["base"]:
    print("PROMOTION_GUARD=PASS bootstrap")
    raise SystemExit(0)

ok=False
if head.startswith("subsection/") and base.startswith("section/"):
    src=head[len("subsection/"):].split("--",1)[0]
    dst=base[len("section/"):]
    ok=(src==dst)
elif head.startswith("section/") and base=="development":
    ok=True
elif head=="development" and base=="testing":
    ok=True
elif head=="testing" and base=="staging":
    ok=True
elif head=="staging" and base=="production":
    ok=True

if not ok:
    print(f"PROMOTION_GUARD=BLOCK head={head} base={base}")
    raise SystemExit(1)

print(f"PROMOTION_GUARD=PASS head={head} base={base}")
