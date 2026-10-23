#!/usr/bin/env python3
"""Score FVRE-Bench-700 predictions against the answer key.

    python3 score.py predictions/<file>.json          # score one file
    python3 score.py                                   # score every file in predictions/

A CWE prediction counts as correct if it names main_cwe OR any accepted_cwes
entry (the MITRE-grounded acceptance family). Detection is scored separately
from CWE naming; CWE accuracy is reported over the truly-vulnerable challenges.
Writes results/<model>.result.json and prints a summary.
"""
from __future__ import annotations
import json, math, re, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEY = json.loads((ROOT / "answer-key.json").read_text())
TRUTH = {c["challenge_id"]: c for c in KEY["challenges"]}


def norm(v):
    if v is None:
        return "N/A"
    t = str(v).strip().upper().replace("_", "-")
    if t in {"N/A", "NA", "NONE", "NULL", ""}:
        return "N/A"
    m = re.search(r"CWE-?(\d+)", t)
    return f"CWE-{int(m.group(1))}" if m else t


def cwe_set(v):
    if v is None:
        return set()
    items = re.findall(r"CWE-?\d+", str(v).upper()) if isinstance(v, str) else v
    out = set()
    for i in items:
        n = norm(i)
        if re.fullmatch(r"CWE-\d+", n):
            out.add(n)
    return out


def label(item):
    v = item.get("is_vulnerable")
    if isinstance(v, bool):
        return v
    c = str(item.get("classification", "")).strip().upper()
    if c in {"VULNERABLE", "VULN", "TRUE"}:
        return True
    if c in {"PATCHED", "NOT_VULNERABLE", "NON_VULNERABLE", "FALSE"}:
        return False
    return None


def wilson(k, n):
    if not n:
        return (0.0, 0.0)
    z, p = 1.959964, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * (c - h), 100 * (c + h))


def r(n, d):
    return n / d if d else 0.0


def score(path: Path) -> dict:
    doc = json.loads(path.read_text())
    preds_list = doc["predictions"] if isinstance(doc, dict) else doc
    P = {p.get("challenge_id"): p for p in preds_list}
    model = doc.get("model", path.stem) if isinstance(doc, dict) else path.stem

    # Score over all 700 challenges. A missing or unanswered challenge counts as
    # wrong (a missed vulnerability, or a false alarm on a patched binary), so a
    # run cannot improve its score by abstaining.
    SCORED = dict(TRUTH)

    tp = tn = fp = fn = abstain = 0
    cwe_any = cwe_main = 0
    addr_hit = 0
    confs, correct = [], []
    by_track = defaultdict(lambda: [0, 0])
    by_arch = defaultdict(lambda: [0, 0])
    by_cwe = defaultdict(lambda: [0, 0])          # [accepted, n] over vulnerable
    missed, false_alarm, wrong_cwe = [], [], []

    for cid, t in SCORED.items():
        p = P.get(cid, {})
        truth = bool(t["is_vulnerable"])
        pl = label(p)
        ok = (pl is truth)
        by_track[t["track"]][0] += int(ok); by_track[t["track"]][1] += 1
        by_arch[t["target"]][0] += int(ok);  by_arch[t["target"]][1] += 1

        if pl is None:
            abstain += 1
            if truth:
                fn += 1; missed.append((cid, t["source_id"], t["main_cwe"]))
            else:
                fp += 1; false_alarm.append((cid, t["source_id"], "N/A"))
        elif truth and pl:
            tp += 1
        elif truth and not pl:
            fn += 1; missed.append((cid, t["source_id"], t["main_cwe"]))
        elif not truth and pl:
            fp += 1; false_alarm.append((cid, t["source_id"], norm(p.get("main_cwe"))))
        else:
            tn += 1

        c = p.get("confidence")
        if isinstance(c, (int, float)):
            confs.append(float(c)); correct.append(1.0 if ok else 0.0)

        if truth:
            accepted = set(t["accepted_cwes"])
            got_main = norm(p.get("main_cwe"))
            got_all = cwe_set(p.get("cwe_subcategories")) | ({got_main} if got_main != "N/A" else set())
            hit = bool(got_all & accepted)
            by_cwe[t["main_cwe"]][0] += int(hit); by_cwe[t["main_cwe"]][1] += 1
            if hit:
                cwe_any += 1
                if got_main == t["main_cwe"]:
                    cwe_main += 1
            elif pl:
                wrong_cwe.append((cid, t["source_id"], got_main or "N/A", t["main_cwe"], sorted(accepted)))
            # localization: only credited when the binary was flagged vulnerable
            if pl and p.get("address"):
                a = str(p["address"]).strip().lower()
                # address ground truth not yet built; record presence for later grading
                if re.fullmatch(r"0x[0-9a-f]+", a):
                    addr_hit += 1

    n = len(SCORED); nv = tp + fn
    acc = 100 * (tp + tn) / n
    lo, hi = wilson(tp + tn, n)
    prec = 100 * r(tp, tp + fp); rec = 100 * r(tp, nv)
    spec = 100 * r(tn, tn + fp); f1 = 100 * r(2 * tp, 2 * tp + fp + fn)
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / den) if den else 0.0
    mean_conf = sum(confs) / len(confs) if confs else 0.0
    brier = sum((c - y) ** 2 for c, y in zip(confs, correct)) / len(confs) if confs else 0.0

    out = {
        "model": model, "file": path.name,
        "tools": doc.get("tools") if isinstance(doc, dict) else None,
        "executed_binaries": doc.get("executed_binaries") if isinstance(doc, dict) else None,
        "host": doc.get("host") if isinstance(doc, dict) else None,
        "n_scored": n, "corpus_total": len(TRUTH), "predictions_in_file": len(P),
        "coverage_pct": round(100*sum(c in P for c in TRUTH)/len(TRUTH),2), "unanalyzed": sum(c not in P for c in TRUTH),
        "abstained": abstain, "addresses_supplied_on_detected": addr_hit,
        "detection": {
            "TP": tp, "TN": tn, "FP": fp, "FN": fn,
            "accuracy_pct": round(acc, 2), "accuracy_95CI": [round(lo, 2), round(hi, 2)],
            "precision_pct": round(prec, 2), "recall_pct": round(rec, 2),
            "specificity_pct": round(spec, 2), "f1_pct": round(f1, 2),
            "mcc": round(mcc, 4),
        },
        "cwe_over_vulnerable": {
            "n": nv,
            "accepted_pct": round(100 * r(cwe_any, nv), 2),
            "exact_main_pct": round(100 * r(cwe_main, nv), 2),
            "accepted_over_detected_pct": round(100 * r(cwe_any, tp), 2),
        },
        "calibration": {"mean_confidence": round(mean_conf, 4), "brier": round(brier, 4)},
        "by_track": {k: {"n": v[1], "acc_pct": round(100 * r(v[0], v[1]), 2)} for k, v in sorted(by_track.items())},
        "by_arch": {k: {"n": v[1], "acc_pct": round(100 * r(v[0], v[1]), 2)} for k, v in sorted(by_arch.items())},
        "cwe_accepted_by_family": {k: {"n": v[1], "accepted_pct": round(100 * r(v[0], v[1]), 2)} for k, v in sorted(by_cwe.items())},
        "missed_vulnerable": missed,
        "false_alarms_on_patched": false_alarm,
        "detected_but_cwe_outside_accepted": wrong_cwe,
    }
    (ROOT / "results").mkdir(exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.stem)
    (ROOT / "results" / f"{safe}.result.json").write_text(json.dumps(out, indent=1) + "\n")
    return out


def show(o):
    d = o["detection"]; c = o["cwe_over_vulnerable"]
    print(f"\n=== {o['model']}  ({o['file']})")
    print(f"  tools={o['tools']}  executed={o['executed_binaries']}  SCORED {o['n_scored']}/{o['corpus_total']} ({o['coverage_pct']}% coverage, {o['unanalyzed']} missing counted wrong)  abstained={o['abstained']}")
    print(f"  DETECTION  acc {d['accuracy_pct']}% (CI {d['accuracy_95CI'][0]}-{d['accuracy_95CI'][1]})  "
          f"prec {d['precision_pct']}%  rec {d['recall_pct']}%  spec {d['specificity_pct']}%  F1 {d['f1_pct']}%  MCC {d['mcc']}")
    print(f"  CWE(vuln)  accepted {c['accepted_pct']}%  exact-main {c['exact_main_pct']}%  accepted/detected {c['accepted_over_detected_pct']}%")
    print(f"  calib      mean-conf {o['calibration']['mean_confidence']}  Brier {o['calibration']['brier']}")
    print(f"  missed {len(o['missed_vulnerable'])}  false-alarms {len(o['false_alarms_on_patched'])}  wrong-CWE {len(o['detected_but_cwe_outside_accepted'])}")
    worst = sorted(o["by_arch"].items(), key=lambda x: x[1]["acc_pct"])[:3]
    print(f"  weakest architectures: " + ", ".join(f"{a} {v['acc_pct']}%" for a, v in worst))


def main():
    args = sys.argv[1:]
    files = [Path(a) for a in args] if args else sorted((ROOT / "predictions").glob("*.json"))
    if not files:
        print("no prediction files found"); return 1
    for f in files:
        show(score(f))
    print(f"\nwrote {len(files)} result file(s) to {ROOT/'results'}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
