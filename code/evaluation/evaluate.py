import csv, json, sys
KEYS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
def load(p):
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"] or "[]"))
            for r in csv.DictReader(open(p, encoding="utf-8"))}
def tup(s): return tuple(s[k] for k in KEYS)

def main(pred_p, gold_p, show=10):
    P, G = load(pred_p), load(gold_p)
    n = len(G); st = seq = 0; tp = fp = fn = 0
    fld = {k: [0, 0] for k in KEYS}; bad = []
    for cid, (gs, gsteps) in G.items():
        ps, psteps = P.get(cid, ("MISSING", []))
        st += ps == gs
        gt, pt = [tup(s) for s in gsteps], [tup(s) for s in psteps]
        seq += gt == pt
        a, b = set(gt), set(pt); tp += len(a & b); fp += len(b - a); fn += len(a - b)
        for i, g in enumerate(gsteps):
            for k in KEYS:
                fld[k][1] += 1
                fld[k][0] += i < len(psteps) and psteps[i][k] == g[k]
        if gt != pt or ps != gs: bad.append((cid, gs, ps, a - b, b - a))
    prec = tp / (tp + fp or 1); rec = tp / (tp + fn or 1); f1 = 2 * prec * rec / (prec + rec or 1)
    rep = [f"# Evaluation report", f"- Status accuracy: {st/n:.3f}", f"- Step F1: {f1:.3f} (P={prec:.3f} R={rec:.3f})",
           f"- Sequence (exact array) accuracy: {seq/n:.3f}"]
    rep += [f"- Field accuracy {k}: {c/(t or 1):.3f}" for k, (c, t) in fld.items()]
    open("evaluation/evaluation_report.md", "w").write("\n".join(rep) + "\n")
    print("\n".join(rep))
    for b in bad[:show]:
        print("\nCASE", b[0], "gold", b[1], "pred", b[2], "\n  MISSING:", sorted(b[3])[:4], "\n  EXTRA:", sorted(b[4])[:4])

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])