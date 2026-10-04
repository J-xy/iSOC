"""Check a soc-triage handoff against assets/handoff.md and the SKILL.md rules.

Usage: python3 tests/check_handoff.py OUTPUT.md INPUT.json [TRANSCRIPT.jsonl] [--expect KEY]
--expect KEY reads tests/expected.json[KEY] for verdict and trap assertions.
Exit code is 0 when no check FAILs.
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SECTIONS = [
    "Verdict", "Recommended action", "What fired and why",
    "Competing explanations", "Evidence requests",
    "What would change this verdict", "Assumptions", "Raw",
]
CALLS = {"Malicious", "Benign", "False positive", "Suspicious — unresolved"}
LEVELS = {"High", "Medium", "Low"}
MODE_LINE = "Mode:** Reason-only — no evidence retrieved."
ISO = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
OPTIONAL_TELEMETRY = re.compile(
    r"data events|flow logs?|server access log|AWS Config|MailItemsAccessed|"
    r"non-interactive|service principal sign-in", re.I)
DEPENDENCY_STATED = re.compile(
    r"not on by default|off by default|not enabled by default|may not be collected|"
    r"not collected by default|separate diagnostic categor|requires .*licen", re.I)
CHAT_TAIL = re.compile(r"let me know|would you like|I can also|hope this|feel free", re.I)

results = []


def record(num, name, ok, detail="", warn=False):
    status = "PASS" if ok else ("WARN" if warn else "FAIL")
    results.append((num, name, status, detail))


def section(text, name):
    m = re.search(rf"^## {re.escape(name)}\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def evidence_items(text):
    body = section(text, "Evidence requests")
    return re.split(r"^\s*\d+\.\s+", body, flags=re.M)[1:]


def check_output(text):
    lines = [l for l in text.strip().splitlines()]
    tail = "\n".join(lines[-5:])
    record(1, "Starts with title, no chat after",
           bool(lines) and lines[0].strip() == "# Alert Triage Handoff" and not CHAT_TAIL.search(tail),
           f"first line: {lines[0][:50]!r}" if lines else "empty output")

    found = re.findall(r"^## (.+?)\s*$", text, re.M)
    record(2, "9 sections in template order", found == SECTIONS,
           "" if found == SECTIONS else f"got {found}")

    record(3, "Reason-only Mode line", MODE_LINE in text)

    call = re.search(r"\*\*Call:\*\*\s*(.+)", text)
    conf = re.search(r"\*\*Confidence:\*\*\s*(\w+)", text)
    sev = re.search(r"\*\*Severity:\*\*\s*(\w+)", text)
    call_v = call.group(1).strip().rstrip(".") if call else None
    ok = call_v in CALLS and conf and conf.group(1) in LEVELS and sev and sev.group(1) in LEVELS
    record(4, "Rubric values", bool(ok),
           f"{call_v} / {conf and conf.group(1)} / {sev and sev.group(1)}")

    expl = section(text, "Competing explanations")
    blocks = re.split(r"(?=^\*\*(?:Benign|Malicious|False positive)\b)", expl, flags=re.M)
    hyps = [b for b in blocks if b.startswith("**")]
    has_b = any(b.startswith("**Benign") for b in hyps)
    has_m = any(b.startswith("**Malicious") for b in hyps)
    missing = [b.splitlines()[0][:60] for b in hyps if "Confirmed if" not in b]
    record(5, "Benign + Malicious, each with Confirmed if",
           has_b and has_m and not missing,
           f"benign={has_b} malicious={has_m} missing-confirmed-if={missing}")

    items = evidence_items(text)
    fields = [re.compile(rf"\b{k}\b[^:\n]{{0,30}}:", re.I) for k in ("Source", "Window", "Resolves")]
    bad = [i + 1 for i, it in enumerate(items) if not all(f.search(it) for f in fields)]
    record(6, "Evidence requests: Source / Window / Resolves",
           bool(items) and not bad, f"{len(items)} requests; incomplete: {bad}")

    bad_w = []
    for i, it in enumerate(items):
        w = re.search(r"Window\b[^:\n]{0,30}:(.*?)(?=\n\s*[-*]*\s*\**\w[\w ,]*:|\Z)", it, re.S)
        w = w.group(1) if w else ""
        stamps = re.findall(ISO, w)
        state = re.search(r"state as of now|in effect at\s+" + ISO, w, re.I)
        absolute = len(stamps) >= 2 or (stamps and re.search(r"\bnow\b", w)) or state
        if not absolute:
            bad_w.append(i + 1)
    record(7, "Absolute windows, both ends", bool(items) and not bad_w,
           f"bad windows: {bad_w}")

    bad_t = [i + 1 for i, it in enumerate(items)
             if OPTIONAL_TELEMETRY.search(it) and not DEPENDENCY_STATED.search(it)]
    record(9, "Off-by-default telemetry flagged", not bad_t,
           f"requests missing dependency note: {bad_t}")


def check_identifiers(text, payload):
    body = text.split("## Raw")[0]
    patterns = {
        "aws key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?!/\d)",
        "guid": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "email": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
        "instance": r"\bi-[0-9a-f]{8,17}\b",
    }
    unknown = sorted({m for p in patterns.values() for m in re.findall(p, body)
                      if m not in payload})
    record(8, "No identifiers absent from payload", not unknown, f"unknown: {unknown}")
    arns = sorted({a.rstrip(".,)`") for a in re.findall(r"arn:aws:[^\s`\"']+", body)
                   if a.rstrip(".,)`") not in payload})
    if arns:
        record("8b", "ARNs not verbatim in payload", False, f"{arns}", warn=True)


def is_skill_listing(command):
    """True when a Bash command only cd's and ls's inside the skill directory."""
    for seg in re.split(r"&&|;|\|\|", command):
        tokens = seg.replace("2>&1", "").split()
        if not tokens:
            continue
        if tokens[0] not in ("cd", "ls"):
            return False
        for tok in tokens[1:]:
            if tok.startswith("-"):
                continue
            if ".." in tok or (tok.startswith("/") and not tok.startswith(str(REPO))):
                return False
    return True


def check_transcript(path):
    bad, listings = [], []
    for line in Path(path).read_text().splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("type") != "assistant":
            continue
        for block in msg.get("message", {}).get("content", []):
            if block.get("type") != "tool_use":
                continue
            name, inp = block["name"], block.get("input", {})
            target = inp.get("file_path") or inp.get("path") or ""
            if name == "Skill":
                continue
            if name in ("Read", "Glob", "Grep") and (not target or str(Path(target).resolve()).startswith(str(REPO))):
                continue
            if name == "Bash" and is_skill_listing(inp.get("command", "")):
                listings.append(inp["command"][:80])
                continue
            bad.append(f"{name}({json.dumps(inp)[:80]})")
    record(10, "Only Skill + Read of skill files", not bad, f"other calls: {bad}")
    if listings:
        record("10b", "Bash listing of skill files", False, f"{listings}", warn=True)


def check_expected(text, key):
    exp = json.loads((REPO / "tests" / "expected.json").read_text())[key]
    call = re.search(r"\*\*Call:\*\*\s*(.+)", text)
    sev = re.search(r"\*\*Severity:\*\*\s*(\w+)", text)
    call_v = call.group(1).strip().rstrip(".") if call else None
    sev_v = sev.group(1) if sev else None
    record(11, "Expected call and severity",
           call_v in exp["calls"] and sev_v == exp["severity"],
           f"got {call_v} / {sev_v}; expected {exp['calls']} / {exp['severity']}")
    body = text.split("## Raw")[0]
    for name, pat in exp.get("must", {}).items():
        hit = re.search(pat, body, re.I)
        record("11", f"must: {name}", bool(hit), "" if hit else f"no match for /{pat}/")
    for name, pat in exp.get("must_not", {}).items():
        hit = re.search(pat, body, re.I)
        record("11", f"must not: {name}", not hit, f"matched {hit.group(0)!r}" if hit else "")


def main():
    args = sys.argv[1:]
    key = None
    if "--expect" in args:
        i = args.index("--expect")
        key = args[i + 1]
        del args[i:i + 2]
    out, inp = Path(args[0]), Path(args[1])
    text, payload = out.read_text(), inp.read_text()
    check_output(text)
    check_identifiers(text, payload)
    if len(args) > 2:
        check_transcript(args[2])
    if key:
        check_expected(text, key)
    results.sort(key=lambda r: (int(re.match(r"\d+", str(r[0])).group()), str(r[0])))
    print(f"| # | Check | Result | Detail |\n|---|---|---|---|")
    for num, name, status, detail in results:
        print(f"| {num} | {name} | {status} | {detail} |")
    sys.exit(1 if any(r[2] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
