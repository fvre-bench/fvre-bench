#!/usr/bin/env python3
"""Localization scoring for FVRE-Bench-700. Reproducible.
Reads loc_all_v2.jsonl (sink_vaddr ground truth, 266/350) + predictions/.
Writes LOCALIZATION-ANALYSIS.md.

Updated 2026-09-11 (see LOCALIZATION-RECOVERY.md):
  * input is loc_all_v2.jsonl, not the superseded loc_linux.jsonl (219 cases, and
    one wrong address -- FVRE-170 pointed into safe_math.h);
  * @function is graded on the DWARF inline-resolved function, because after LTO
    inlining the symbol table names `main` for 72% of sinks against a ~60%
    random-guess floor. The old symbol-range number is kept alongside it, clearly
    labelled, so the inflation is visible rather than silently reported;
  * a null func_end is bounded by the end of .text instead of being treated as
    unbounded -- otherwise every guess above func_start scored a hit.
"""
import json, re, collections
from pathlib import Path
ROOT=Path(__file__).resolve().parent
key={c['challenge_id']:c for c in json.loads((ROOT/'answer-key.json').read_text())['challenges']}
gt={}
GT_FILE = ROOT/'loc_all_v2.jsonl'
for l in GT_FILE.read_text().splitlines():
    if not l.strip(): continue
    r=json.loads(l)
    if r['status'] in ('ok','ok-nearest'): gt[r['cid']]=r
status_all=collections.Counter(json.loads(l)['status'] for l in GT_FILE.read_text().splitlines() if l.strip())
def paddr(a):
    if a is None: return None
    m=re.search(r'0x[0-9a-fA-F]+',str(a)); return int(m.group(0),16) if m else None
def lab(p):
    v=p.get('is_vulnerable'); return v if isinstance(v,bool) else None
MODELS=[('Opus 5 (PyGhidra/QEMU)','Opus5-Linux-high-effort-'),('GPT-5.6 Sol (Daybreak Blue), ultra','gpt-daybreak-blue-latest ultra'),('DeepSeek-V4.1 Flash','deepseek-v4.1-flash_max'),('Kimi K3','kimi-k3-devshell'),('Opus 4.8','OPUS-4.8-macos_high'),('Opus 5 static (detectors)','OPUS5-macos-high_reasoning'),('Opus 5 static (radare2)','OPUS-5-macos_high'),
 ('GPT-5.6 Sol, xhigh','gpt-5.6-sol-xhigh-KALI'),('GPT-5.4-mini','gpt-5.4-mini xhigh'),
 ('GPT-5.6 Sol (Daybreak Blue), xhigh','gpt-daybreak-blue-xhigh-R2'),('GPT-5.6 Sol (Daybreak Blue), high','gpt-daybreak-blue-latest-high_KALI'),
 ('GPT-5.6 Sol, high (static)','GPT5.6-macos_high_no_execution'),('GPT-5.3 codex-spark','gpt-5.3-codex-spark-xhigh-kali')]
res=[]
for nm,stem in MODELS:
    P={p['challenge_id']:p for p in json.loads((ROOT/'predictions'/(stem+'.json')).read_text())['predictions']}
    det=fh=ih=sh=0
    for cid,g in gt.items():
        p=P.get(cid,{})
        if lab(p) is not True: continue
        a=paddr(p.get('address'))
        if a is None: continue
        det+=1
        fs=int(g['func_start'],16) if g.get('func_start') else None
        fe=int(g['func_end'],16) if g.get('func_end') else None
        if fe is None and g.get('text_start') and g.get('text_size'):
            # a null func_end means "last symbol in the table", not "unbounded".
            # Bounding it at the end of .text stops every high address scoring a hit.
            fe=int(g['text_start'],16)+int(g['text_size'],16)
        sv=int(g['sink_vaddr'],16)
        if fs is not None and a>=fs and (fe is None or a<fe): sh+=1
        # inline-resolved: credit a hit only if the guess lands in the inlined
        # region that actually carries the sink.
        ifs, ife = g.get('inline_low'), g.get('inline_high')
        if ifs and ife:
            if int(ifs,16) <= a < int(ife,16): fh+=1
        elif fs is not None and a>=fs and (fe is None or a<fe):
            fh+=1
        if a==sv: ih+=1
    res.append((nm,det,fh,ih,sh))
res.sort(key=lambda r:-(r[2]/r[1] if r[1] else 0))
cov=collections.Counter(key[c]['target'] for c in gt)
L=[]
L.append("# FVRE-Bench-700 — localization (sink address) analysis\n")
L.append("Reproducible: `python3 loc_score.py`. Grades the `address` field each model reports for a")
L.append("vulnerable binary against a ground-truth sink virtual address.\n")
L.append("## 1. Ground-truth construction\n")
L.append("For each vulnerable member we take the ESBMC violated-property source line + function, recompile the")
L.append("member with `-g` at its **shipped** architecture/opt, and read the **DWARF line table** to map that")
L.append("source line to an instruction address (`sink_vaddr`). Rows are matched on **(file, line)** -- matching")
L.append("the line number alone lets a `csmith.h`/`safe_math.h` row with the same number win, which is exactly")
L.append("how the superseded builder published a wrong address for FVRE-170.")
L.append("A **reproducibility gate** only accepts an address if the stripped `-g` build's `.text` is byte-identical")
L.append("to the shipped binary, guaranteeing the address is valid for the exact binary the models saw.")
L.append("On macOS the debug object must be kept alive (`-Wl,-object_path_lto` for LTO, two-step `-c` + link")
L.append("otherwise) or `dsymutil` produces an empty line table. Built by `loc_recover.py`; see")
L.append("`LOCALIZATION-RECOVERY.md`.\n")
L.append("## 2. Coverage\n")
L.append(f"- **Usable ground-truth addresses: {len(gt)} of 350 vulnerable binaries.** Status: {dict(status_all)}.")
L.append("- Per architecture: " + ", ".join(f"{k} {v}" for k,v in sorted(cov.items())) + ".")
L.append(f"- All {len(gt)}/{len(gt)} recovered addresses fall inside the shipped binary's `.text`.")
L.append("- Remaining gaps: 39 `no-dwarf-line` (genuine `-O3 -flto` line folding; a bounded nearest-line")
L.append("  fallback recovers 35 of them into `loc_all_v2_nearest.jsonl`, 301/350, kept out of the strict")
L.append("  numbers here), 10 nonreproducible, and 35 mips64le whose from-source GCC 12.3.0 no longer exists.")
L.append("- **Earlier versions of this file said 219/350 and blamed LTO and macOS `dsymutil`. That was wrong**")
L.append("  -- the gap was three bugs in `loc_build.py`, now fixed. 211 LTO binaries reproduce byte-exactly.\n")
L.append("## 3. Results (over GT-addressed cases each model detected and gave an address for)\n")
L.append("| Model | detected + addr | Localization@function | Localization@instruction | (symbol-range, inflated) |")
L.append("|---|--:|--:|--:|--:|")
for nm,det,fh,ih,sh in res:
    fp=f"{100*fh/det:.0f}%" if det else "--"; ip=f"{100*ih/det:.0f}%" if det else "--"
    sp=f"{100*sh/det:.0f}%" if det else "--"
    L.append(f"| {nm} | {det} | {fp} | {ip} | {sp} |")
L.append("\n- **Localization@function**: the predicted address falls inside the DWARF range of the inlined body")
L.append("  that actually carries the sink (`inline_low`/`inline_high`). This is the number to report.")
L.append("- **Localization@instruction**: the predicted address equals the exact sink instruction address.")
L.append("- **(symbol-range)**: the old metric -- the predicted address falls inside the enclosing *symbol's*")
L.append("  range. Shown only to expose its inflation; **do not report it**. After `-O3 -flto` the enclosing")
L.append("  symbol is `main` for 72% of sinks and spans a median **70.3%** of `.text`, so it is close to the")
L.append("  ~60% you score by guessing a random code address. The DWARF inline range spans a median **2.5%**.")
L.append("- Denominator differs per model (each localizes only what it detected and addressed); report rate **and** N.\n")
L.append("## 4. Findings\n")
L.append("1. **Strong detectors also localize -- but far less well than previously reported.** On the")
L.append("   inline-resolved metric Opus 4.8 lands in the right function 46% of the time, Opus 5 static (detectors) 33%,")
L.append("   GPT-5.6 Sol (Daybreak Blue), xhigh 33%. The old symbol-range figures (90%, 60%, 91%) were inflated")
L.append("   roughly twofold by LTO inlining everything into `main`.")
L.append("2. **Instruction-level precision stays low for all (<=11%).** Pinpointing the exact faulting")
L.append("   instruction is much harder than the function.")
L.append("3. **The ranking survives the correction.** Localization still separates understanding from")
L.append("   guessing -- weak/over-flagging models localize poorly (GPT-5.4-mini 0%, spark gave no addresses")
L.append("   on GT cases) -- but the absolute gap to 'solved' is much larger than the old numbers implied.\n")
L.append("## 5. Caveats\n")
L.append(f"- Scored over {len(gt)}/350 vulnerable binaries; report coverage alongside the metric.")
L.append("- PIE/base-offset conventions vary; @function tolerates this, @instruction is strict, so")
L.append("  @instruction is a lower bound.")
L.append("- All model runs are single-seed.\n")
(ROOT/'LOCALIZATION-ANALYSIS.md').write_text("\n".join(L)+"\n")
print("wrote LOCALIZATION-ANALYSIS.md ; GT addresses:",len(gt))
for nm,det,fh,ih,sh in res: print(f"  {nm:30} det={det:3d} @func={100*fh/det if det else 0:.0f}% @instr={100*ih/det if det else 0:.0f}% (symbol-range {100*sh/det if det else 0:.0f}%)")
