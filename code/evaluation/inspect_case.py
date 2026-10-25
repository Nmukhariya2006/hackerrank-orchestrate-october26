# usage: python evaluation/inspect_case.py case_11
import csv, json, sys, os
sys.path.insert(0, "code")
from evidence import read_units, RID
cid = sys.argv[1]
gold = {r["case_id"]: json.loads(r["steps_json"] or "[]")
        for r in csv.DictReader(open("dataset/sample_output.csv", encoding="utf-8"))}[cid]
want = {s["resource_id"] for s in gold}
print("gold resources:", sorted(want))
for f in csv.DictReader(open("dataset/evidence_files.csv", encoding="utf-8")):
    for u in read_units("dataset/" + f["file_path"]):
        if want & set(RID.findall(u)):
            print(f"[{f['file_id']}] {u[:300]}")