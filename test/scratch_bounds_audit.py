#!/usr/bin/env python3
"""Static bounds audit for DharaFS's scratch-buffer accessors.

DharaFS has no hand-written assembly (unlike DhruvaOS, whose
test/asm_safety_audit.py covers register-clobber-after-call and
push/pop stack-balance bugs in boot/*.S) -- its runtime/*.c files are
plain, generated-looking C, and buf_primitives.vani's own
buf_read_byte/buf_write_byte/buf_read_u32/buf_write_u32/buf_checksum
give vani code completely UNCHECKED raw pointer+offset access into
those C buffers, by design (see runtime/dharafs_runtime.c's own header
comment: "no bounds checking -- callers are trusted to stay within the
scratch buffer they were handed"). That design choice moves the real
bug class from "assembly register misuse" to "an offset expression on
the vani side that can exceed the C buffer's real size" -- a silent,
out-of-bounds C write/read into whatever static data happens to sit
next in memory. This tool finds that bug class, for the subset of call
sites it can statically resolve.

Two checks, matching this project's own asm_safety_audit.py in spirit
(DEFINITE = zero false positives possible; REVIEW = a real, traceable
risk that still needs a human's eyes):

  1. LITERAL OVERRUN (DEFINITE): a direct accessor-call site (e.g.
     buf_write_u32(sha256_h_scratch_get(), 40 as u32, v)) whose offset
     is a closed arithmetic expression of integer literals only, and
     offset + access_width exceeds the buffer's real, physical
     capacity (the C side's actual array size, which SCRATCH_BUF's own
     `((SIZE)+7)/8` rounds UP to an 8-byte boundary -- so the audit
     checks against that rounded physical capacity, not the smaller
     documented SIZE, to avoid flagging harmless padding reads/writes
     as a real memory-safety bug). Unconditionally reachable, no
     hypotheticals: this is a real out-of-bounds C access every time
     that line runs.

  2. LOOP-BOUND OVERRUN (REVIEW): a direct accessor-call site whose
     offset expression contains exactly one variable, used inside an
     enclosing `while VAR < BOUND { ... }` loop (BOUND itself a
     literal), substituting VAR -> BOUND-1 (the loop's own maximum
     reachable value, assuming VAR only increments -- true of every
     loop shape seen in this codebase, but not verified independently
     per call site, hence REVIEW not DEFINITE) and evaluating the same
     offset expression at that substituted value. Flagged only if the
     substituted result exceeds the buffer's physical capacity.

SCOPE, documented rather than silently pretended away (the same
"documented gap over silent skip" precedent DhruvaOS's own build.sh
already sets for its own per-task stack-depth gate): this tool only
resolves call sites whose FIRST ARGUMENT is a direct, inline call to a
known SCRATCH_BUF/SCRATCH_BUF_PTR accessor (e.g. `sha256_h_scratch_get()`
appearing literally in the call). A great many real call sites in this
codebase pass the buffer through a function parameter instead (e.g.
`fn sha256_k_init(k: mut ref i64)` then `buf_write_u32(k, ...)`) --
resolving those would require real interprocedural data-flow tracing
of which buffer a given caller passed as `k`, which this tool does not
attempt. Those call sites are silently NOT covered; this is a real,
open gap, not a false claim of full coverage.
"""
import argparse
import glob
import os
import re
import sys

SCRATCH_BUF_RE = re.compile(
    r"#define\s+(SCRATCH_BUF(?:_PTR)?)\s*\(NAME,\s*SIZE\)"
)
# Matches one macro invocation: SCRATCH_BUF(name, 256) or SCRATCH_BUF_PTR(name, 64)
INVOKE_RE = re.compile(
    r"^\s*(SCRATCH_BUF(?:_PTR)?)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(\d+)\s*\)\s*$"
)

BUF_FN_WIDTH = {
    "buf_write_u32": 4,
    "buf_read_u32": 4,
    "buf_write_byte": 1,
    "buf_read_byte": 1,
}
BUF_FNS = tuple(BUF_FN_WIDTH) + ("buf_checksum",)

WHILE_RE = re.compile(r"while\s+([A-Za-z_][A-Za-z0-9_]*)\s*<\s*(\d+)\s*\{")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CLOSED_ARITH_RE = re.compile(r"^[0-9+\-*()\s]+$")


def parse_c_scratch_buffers(runtime_dir):
    """-> {accessor_fn_name: (declared_size, physical_capacity)}"""
    buffers = {}
    for path in sorted(glob.glob(os.path.join(runtime_dir, "*.c"))):
        with open(path) as f:
            lines = f.readlines()
        # Macro suffix (_get vs _ptr) is fixed per #define in this file,
        # keyed by macro name (SCRATCH_BUF vs SCRATCH_BUF_PTR).
        macro_suffix = {}
        for line in lines:
            m = SCRATCH_BUF_RE.search(line)
            if m:
                macro_suffix[m.group(1)] = None  # filled in below by scanning the body
        # The suffix is baked into the macro body two lines down
        # (`NAME##_get`/`NAME##_ptr`); rather than parse the macro body
        # generically, hard-code the two shapes actually used in this
        # codebase (both fixed, documented conventions).
        macro_suffix = {"SCRATCH_BUF": "_get", "SCRATCH_BUF_PTR": "_ptr"}
        for line in lines:
            m = INVOKE_RE.match(line)
            if not m:
                continue
            macro, name, size_s = m.group(1), m.group(2), m.group(3)
            size = int(size_s)
            capacity = ((size + 7) // 8) * 8
            accessor = name + macro_suffix[macro]
            buffers[accessor] = (size, capacity, path)
    return buffers


def find_matching_paren(text, open_idx):
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top_level_args(arglist):
    args = []
    depth = 0
    cur = []
    for ch in arglist:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append("".join(cur).strip())
    return args


def strip_casts(expr):
    expr = expr.strip()
    while True:
        m = re.match(r"^\((.*)\)$", expr)
        if m and find_matching_paren(expr, 0) == len(expr) - 1:
            expr = m.group(1).strip()
            continue
        m = re.match(r"^(.*?)\s+as\s+(?:u32|i64|u8|i32)$", expr)
        if m:
            expr = m.group(1).strip()
            continue
        break
    return expr


def eval_closed_arith(expr):
    """Return an int if expr is a closed integer arithmetic expression
    (digits/+/-/*/parens only, no identifiers), else None. Safe: the
    character-class check below runs BEFORE eval() ever sees the
    string, so no identifier, attribute, or call syntax can reach it."""
    expr = strip_casts(expr)
    if not expr:
        return None
    if not CLOSED_ARITH_RE.match(expr):
        return None
    try:
        return int(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return None


def resolve_accessor(arg_expr, buffers):
    for name in buffers:
        if re.search(r"\b" + re.escape(name) + r"\s*\(\s*\)", arg_expr):
            return name
    return None


def find_enclosing_while_bound(lines, call_idx, var):
    for i in range(call_idx, -1, -1):
        m = WHILE_RE.search(lines[i])
        if m and m.group(1) == var:
            return int(m.group(2))
    return None


def eval_with_substitution(expr, var, value):
    expr = strip_casts(expr)
    substituted = re.sub(r"\b" + re.escape(var) + r"\b", str(value), expr)
    return eval_closed_arith(substituted)


def scan_vani_file(path, buffers):
    with open(path) as f:
        lines = f.readlines()
    findings = []
    for idx, line in enumerate(lines):
        if "extern" in line:
            continue
        for fn in BUF_FNS:
            call_pos = line.find(fn + "(")
            if call_pos == -1:
                continue
            open_paren = call_pos + len(fn)
            close_paren = find_matching_paren(line, open_paren)
            if close_paren == -1:
                continue  # multi-line call, out of scope (none exist today -- see header)
            arglist = line[open_paren + 1:close_paren]
            args = split_top_level_args(arglist)
            accessor = resolve_accessor(args[0], buffers) if args else None
            if not accessor:
                continue  # buffer reached via a parameter, not a direct call -- documented gap
            size, capacity, cpath = buffers[accessor]

            if fn == "buf_checksum":
                if len(args) < 3:
                    continue
                start_v = eval_closed_arith(args[1])
                len_v = eval_closed_arith(args[2])
                if start_v is None or len_v is None:
                    continue
                end = start_v + len_v
                if end > capacity:
                    findings.append(dict(
                        severity="DEFINITE", file=path, line=idx + 1,
                        accessor=accessor, cfile=cpath,
                        msg=(f"buf_checksum(({accessor}), start={start_v}, "
                             f"len={len_v}) touches byte {end - 1}, but "
                             f"{accessor}'s physical capacity is only "
                             f"{capacity} bytes (declared size {size})")))
                continue

            width = BUF_FN_WIDTH[fn]
            offset_expr = args[1]
            lit = eval_closed_arith(offset_expr)
            if lit is not None:
                if lit + width > capacity:
                    findings.append(dict(
                        severity="DEFINITE", file=path, line=idx + 1,
                        accessor=accessor, cfile=cpath,
                        msg=(f"{fn}({accessor}, {lit}) accesses bytes "
                             f"[{lit}, {lit + width}), but {accessor}'s "
                             f"physical capacity is only {capacity} bytes "
                             f"(declared size {size})")))
                continue

            idents = set(IDENT_RE.findall(strip_casts(offset_expr)))
            if len(idents) != 1:
                continue  # 0 or >1 variables -- not a pattern this tool resolves
            var = next(iter(idents))
            bound = find_enclosing_while_bound(lines, idx, var)
            if bound is None:
                continue
            max_val = eval_with_substitution(offset_expr, var, bound - 1)
            if max_val is None:
                continue
            if max_val + width > capacity:
                findings.append(dict(
                    severity="REVIEW", file=path, line=idx + 1,
                    accessor=accessor, cfile=cpath,
                    msg=(f"{fn}({accessor}, {offset_expr}) inside "
                         f"`while {var} < {bound}` reaches offset "
                         f"{max_val} at {var}={bound - 1}, accessing bytes "
                         f"[{max_val}, {max_val + width}), but {accessor}'s "
                         f"physical capacity is only {capacity} bytes "
                         f"(declared size {size}) -- REVIEW: assumes {var} "
                         f"only increments within this loop, not "
                         f"independently verified per call site")))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime-dir", default=os.path.join(os.path.dirname(__file__), "..", "runtime"))
    ap.add_argument("--src-dir", default=os.path.join(os.path.dirname(__file__), "..", "src"))
    args = ap.parse_args()

    buffers = parse_c_scratch_buffers(args.runtime_dir)
    if not buffers:
        print(f"WARNING: no SCRATCH_BUF/SCRATCH_BUF_PTR accessors found under {args.runtime_dir}")

    vani_files = sorted(glob.glob(os.path.join(args.src_dir, "*.vani")))
    all_findings = []
    for path in vani_files:
        all_findings.extend(scan_vani_file(path, buffers))

    print(f"Parsed {len(buffers)} scratch-buffer accessors from {args.runtime_dir}.")
    print(f"Scanned {len(vani_files)} .vani files under {args.src_dir}.")

    definite = [f for f in all_findings if f["severity"] == "DEFINITE"]
    review = [f for f in all_findings if f["severity"] == "REVIEW"]

    print(f"\n=== DEFINITE ({len(definite)}) ===")
    for f in definite:
        print(f"  [{os.path.relpath(f['file'])}:{f['line']}] {f['msg']}")

    print(f"\n=== REVIEW ({len(review)}) ===")
    for f in review:
        print(f"  [{os.path.relpath(f['file'])}:{f['line']}] {f['msg']}")

    return 1 if definite else 0


if __name__ == "__main__":
    sys.exit(main())
