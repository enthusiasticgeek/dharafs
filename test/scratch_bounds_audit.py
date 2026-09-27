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
next in memory. This tool finds that bug class.

Two offset checks, matching this project's own asm_safety_audit.py in
spirit (DEFINITE = zero false positives possible; REVIEW = a real,
traceable risk that still needs a human's eyes):

  1. LITERAL OVERRUN: a call site's offset is a closed arithmetic
     expression of integer literals only, and offset + access_width
     exceeds the buffer's real, physical capacity (the C side's actual
     array size, which SCRATCH_BUF's own `((SIZE)+7)/8` rounds UP to an
     8-byte boundary -- so the audit checks against that rounded
     physical capacity, not the smaller documented SIZE, to avoid
     flagging harmless padding reads/writes as a real memory-safety
     bug).

  2. LOOP-BOUND OVERRUN: an offset expression containing exactly one
     variable, used inside an enclosing `while VAR < BOUND { ... }`
     loop (BOUND itself a literal), substituting VAR -> BOUND-1 (the
     loop's own maximum reachable value, assuming VAR only increments)
     and evaluating the same offset expression at that substituted
     value. Flagged only if the substituted result exceeds capacity.

BUFFER RESOLUTION, in two tiers:

  DIRECT (severity DEFINITE for check 1, REVIEW for check 2): the call
  site's first argument is a direct, inline call to a known
  SCRATCH_BUF/SCRATCH_BUF_PTR accessor, e.g.
  `buf_write_u32(sha256_h_scratch_get(), 40 as u32, v)`.

  INTERPROCEDURAL (always REVIEW, even for check 1 -- the buffer
  identity itself is inferred, not observed, so a resolution mistake
  could otherwise masquerade as a false DEFINITE): the first argument
  is a bare identifier -- a local variable or function parameter, e.g.
  `fn sha256_k_init(k: mut ref i64) { buf_write_u32(k, ...); }`. This
  tool traces such an identifier backward: if it's a local variable,
  find its own `let IDENT = EXPR;` (or a later `IDENT = EXPR;`
  reassignment) and recurse on EXPR; if it's a function parameter,
  find every call site of that function and recurse on the
  corresponding argument expression at each one, unioning the results
  (a function called with different buffers from different sites is
  a real, common pattern here -- e.g. core.vani's generic
  read_be32/write_be32 helpers -- so resolution returns a SET of
  candidate buffers, and each candidate is checked independently).
  Bounded to MAX_DEPTH hops with a recursion guard (cycles resolve to
  the empty set) and memoized per (function, parameter) pair.

  Both tiers can still fail to resolve (an identifier that's neither a
  traceable local nor a parameter of a function whose own callers are
  all traceable -- e.g. a value from a consumer-provided extern hook,
  or a local reassigned to something this tool doesn't parse). That
  remains a real, open, and now much smaller gap -- run with
  --log-level=DEBUG to see exactly which call sites hit it and why.
"""
import argparse
import glob
import logging
import os
import re
import sys

log = logging.getLogger("scratch_bounds_audit")

SCRATCH_BUF_RE = re.compile(
    r"#define\s+(SCRATCH_BUF(?:_PTR)?)\s*\(NAME,\s*SIZE\)"
)
INVOKE_RE = re.compile(
    r"^\s*(SCRATCH_BUF(?:_PTR)?)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(\d+)\s*\)\s*$"
)
# A hand-written (non-macro) scratch buffer, the same shape SCRATCH_BUF
# itself generates: `static int64_t g_NAME[(SIZE + 7) / 8];` paired
# with `int64_t *ACCESSOR(void) { return g_NAME; }` (not necessarily
# adjacent lines) -- e.g. runtime/dharafs_fsqueue_runtime.c's own
# fsqueue_path_scratch_get/fsqueue_data_scratch_get, written by hand
# rather than through the macro. Missing these was a real gap: the
# tool silently couldn't resolve any call site touching them.
STORAGE_DECL_RE = re.compile(
    r"static\s+int64_t\s+(\w+)\s*\[\s*\(\s*(\d+)\s*\+\s*7\s*\)\s*/\s*8\s*\]\s*;"
)
HANDWRITTEN_ACCESSOR_RE = re.compile(
    r"int64_t\s*\*\s*(\w+)\s*\(void\)\s*\{\s*return\s+(\w+)\s*;\s*\}"
)

BUF_FN_WIDTH = {
    "buf_write_u32": 4,
    "buf_read_u32": 4,
    "buf_write_byte": 1,
    "buf_read_byte": 1,
}
BUF_FNS = tuple(BUF_FN_WIDTH) + ("buf_checksum",)

FN_DEF_RE = re.compile(
    r"^\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
)
WHILE_RE = re.compile(r"while\s+([A-Za-z_][A-Za-z0-9_]*)\s*<\s*(\d+)\s*\{")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
IDENT_ONLY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLOSED_ARITH_RE = re.compile(r"^[0-9+\-*()\s]+$")
VANI_KEYWORDS = {"if", "while", "let", "return", "fn", "extern", "else"}

MAX_DEPTH = 8


def parse_c_scratch_buffers(runtime_dir):
    """-> {accessor_fn_name: (declared_size, physical_capacity, c_file)}"""
    buffers = {}
    for path in sorted(glob.glob(os.path.join(runtime_dir, "*.c"))):
        with open(path) as f:
            lines = f.readlines()
        # The _get/_ptr suffix is baked into each macro's own body
        # (`NAME##_get` vs `NAME##_ptr`); both macro shapes used in
        # this codebase are fixed, documented conventions, so hard-code
        # them rather than parse the macro body generically.
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

        storage_sizes = {m.group(1): int(m.group(2)) for m in STORAGE_DECL_RE.finditer("".join(lines))}
        for m in HANDWRITTEN_ACCESSOR_RE.finditer("".join(lines)):
            accessor, varname = m.group(1), m.group(2)
            if accessor in buffers or varname not in storage_sizes:
                continue
            size = storage_sizes[varname]
            capacity = ((size + 7) // 8) * 8
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


def find_matching_brace(lines, start_line_idx, open_col):
    depth = 0
    for i in range(start_line_idx, len(lines)):
        line = lines[i]
        j = open_col if i == start_line_idx else 0
        while j < len(line):
            if line[j] == "{":
                depth += 1
            elif line[j] == "}":
                depth -= 1
                if depth == 0:
                    return i
            j += 1
    return len(lines) - 1


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


def enclosing_block_headers(lines, call_idx, floor_idx):
    """Every block header (`while ... {`, `if ... {`, `fn ... {`) lexically
    enclosing call_idx, innermost first, found by walking backward and
    tracking brace depth -- NOT just "nearest textually-preceding
    `while` line", which would wrongly match a sibling loop that has
    already closed, or (unbounded) a completely unrelated EARLIER
    function's own loop reusing the same variable name. Every `{`/`}`
    in this codebase's own style is either alone on its line or part of
    a single-line, self-balanced `if cond { a } else { b }` expression
    (verified: no line here has an unbalanced open/close mix beyond
    that shape), so whole-line net open/close counting is exact."""
    headers = []
    depth = 0
    i = call_idx - 1
    while i >= floor_idx:
        line = lines[i]
        net = line.count("{") - line.count("}")
        if net == 0:
            i -= 1
            continue
        if net < 0:
            depth += -net
            i -= 1
            continue
        # net > 0: this line opens a block (fn/while/if header).
        if depth >= net:
            depth -= net
            i -= 1
            continue
        headers.append((i, line))
        depth = 0
        i -= 1
    return headers


def find_enclosing_while_bound(lines, call_idx, var, floor_idx):
    for i, line in enclosing_block_headers(lines, call_idx, floor_idx):
        m = WHILE_RE.search(line)
        if m and m.group(1) == var:
            return int(m.group(2))
    return None


def eval_with_substitution(expr, var, value):
    expr = strip_casts(expr)
    substituted = re.sub(r"\b" + re.escape(var) + r"\b", str(value), expr)
    return eval_closed_arith(substituted)


# ---- Interprocedural buffer-identity tracing ----

def parse_function_defs(vani_files):
    """-> {name: {"file", "lines", "start", "end", "params"}} for every
    non-extern `fn` (extern fns have no body to trace through -- they
    are natural resolution dead-ends, correctly left unresolved)."""
    defs = {}
    for path in vani_files:
        with open(path) as f:
            lines = f.readlines()
        for idx, line in enumerate(lines):
            if "extern" in line:
                continue
            m = FN_DEF_RE.match(line)
            if not m:
                continue
            name, paramlist = m.group(1), m.group(2)
            brace_col = line.find("{")
            if brace_col == -1:
                continue  # signature split across lines -- none exist today, documented gap
            end = find_matching_brace(lines, idx, brace_col)
            params = []
            for p in split_top_level_args(paramlist):
                p = p.strip()
                if not p:
                    continue
                params.append(p.split(":")[0].strip())
            defs[name] = dict(file=path, lines=lines, start=idx, end=end, params=params)
    return defs


def parse_call_sites(function_defs):
    """-> {callee_name: [(caller_name, line_idx, arg_exprs), ...]}"""
    known_names = set(function_defs) | set(BUF_FNS)
    sites = {}
    for caller_name, d in function_defs.items():
        lines = d["lines"]
        for idx in range(d["start"], d["end"] + 1):
            line = lines[idx]
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", line):
                name = m.group(1)
                if name not in known_names or name in VANI_KEYWORDS:
                    continue
                # Skip the function's own `fn NAME(` definition line.
                prefix = line[:m.start()].rstrip()
                if prefix.endswith("fn"):
                    continue
                open_paren = m.end() - 1
                close_paren = find_matching_paren(line, open_paren)
                if close_paren == -1:
                    continue
                arg_exprs = split_top_level_args(line[open_paren + 1:close_paren])
                sites.setdefault(name, []).append((caller_name, idx, arg_exprs))
    return sites


LET_OR_ASSIGN_RE = re.compile(
    r"^\s*(?:let\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*[^=]+)?|([A-Za-z_][A-Za-z0-9_]*))\s*=\s*(?!=)(.+?);"
)


def find_last_assignment(func_def, ident, before_line_idx):
    """Flow-insensitive (last textual assignment above before_line_idx
    wins, ignoring branch structure) -- an approximation, not a real
    reaching-definitions analysis. Adequate here: every finding this
    produces is REVIEW-tier, never DEFINITE, precisely because this
    approximation could be wrong."""
    result = None
    for i in range(func_def["start"], before_line_idx):
        line = func_def["lines"][i]
        m = LET_OR_ASSIGN_RE.match(line)
        if not m:
            continue
        name = m.group(1) or m.group(2)
        if name == ident:
            result = (m.group(3), i)
    return result


def resolve_expr(expr, func_name, before_line_idx, function_defs, buffers, call_sites, depth, memo, in_progress):
    expr = strip_casts(expr)
    direct = resolve_accessor(expr, buffers)
    if direct:
        log.debug("%*sresolved %r -> accessor %s (direct)", depth * 2, "", expr, direct)
        return frozenset({direct})

    if not IDENT_ONLY_RE.match(expr):
        log.debug("%*sunresolved: %r is not a bare identifier or known accessor", depth * 2, "", expr)
        return frozenset()

    if depth > MAX_DEPTH:
        log.debug("%*sunresolved: %r -- MAX_DEPTH exceeded", depth * 2, "", expr)
        return frozenset()

    func_def = function_defs.get(func_name)
    if func_def is None:
        log.debug("%*sunresolved: %r -- %s has no traceable body (extern/unknown)", depth * 2, "", expr, func_name)
        return frozenset()

    found = find_last_assignment(func_def, expr, before_line_idx)
    if found is not None:
        rhs, rhs_line = found
        log.debug("%*s%s: local %r = %r at %s:%d", depth * 2, "", func_name, expr, rhs, func_def["file"], rhs_line + 1)
        return resolve_expr(rhs, func_name, rhs_line, function_defs, buffers, call_sites, depth + 1, memo, in_progress)

    if expr in func_def["params"]:
        idx = func_def["params"].index(expr)
        return resolve_param(func_name, idx, function_defs, buffers, call_sites, depth + 1, memo, in_progress)

    log.debug("%*sunresolved: %r in %s is neither a traceable local nor a parameter", depth * 2, "", expr, func_name)
    return frozenset()


def resolve_param(func_name, param_idx, function_defs, buffers, call_sites, depth, memo, in_progress):
    key = (func_name, param_idx)
    if key in memo:
        return memo[key]
    if key in in_progress:
        log.debug("%*srecursion guard hit for %s(param %d)", depth * 2, "", func_name, param_idx)
        return frozenset()
    if depth > MAX_DEPTH:
        log.debug("%*sMAX_DEPTH exceeded resolving %s(param %d)", depth * 2, "", func_name, param_idx)
        return frozenset()

    in_progress.add(key)
    results = set()
    sites = call_sites.get(func_name, [])
    if not sites:
        log.debug("%*s%s(param %d): no call sites found -- never called, or called only from"
                  " outside the traced src tree", depth * 2, "", func_name, param_idx)
    for caller_name, line_idx, arg_exprs in sites:
        if param_idx >= len(arg_exprs):
            continue
        log.debug("%*s%s(param %d) <- call from %s:%d: arg=%r",
                  depth * 2, "", func_name, param_idx, caller_name, line_idx + 1, arg_exprs[param_idx])
        results |= resolve_expr(arg_exprs[param_idx], caller_name, line_idx, function_defs, buffers, call_sites, depth + 1, memo, in_progress)
    in_progress.discard(key)
    memo[key] = frozenset(results)
    return memo[key]


def check_offset(fn, offset_expr, width, capacity, size, accessor, lines, idx, severity, floor_idx):
    lit = eval_closed_arith(offset_expr)
    if lit is not None:
        if lit + width > capacity:
            return dict(
                severity=severity, line=idx + 1, accessor=accessor,
                msg=(f"{fn}({accessor}, {lit}) accesses bytes "
                     f"[{lit}, {lit + width}), but {accessor}'s "
                     f"physical capacity is only {capacity} bytes "
                     f"(declared size {size})"))
        return None

    idents = set(IDENT_RE.findall(strip_casts(offset_expr)))
    if len(idents) != 1:
        return None
    var = next(iter(idents))
    bound = find_enclosing_while_bound(lines, idx, var, floor_idx)
    if bound is None:
        return None
    max_val = eval_with_substitution(offset_expr, var, bound - 1)
    if max_val is None:
        return None
    if max_val + width > capacity:
        return dict(
            severity="REVIEW", line=idx + 1, accessor=accessor,
            msg=(f"{fn}({accessor}, {offset_expr}) inside "
                 f"`while {var} < {bound}` reaches offset "
                 f"{max_val} at {var}={bound - 1}, accessing bytes "
                 f"[{max_val}, {max_val + width}), but {accessor}'s "
                 f"physical capacity is only {capacity} bytes "
                 f"(declared size {size}) -- REVIEW: assumes {var} "
                 f"only increments within this loop, not "
                 f"independently verified per call site"))
    return None


def scan_vani_file(path, buffers, function_defs, call_sites):
    with open(path) as f:
        lines = f.readlines()
    findings = []
    stats = dict(total_calls=0, resolved_direct=0, resolved_indirect=0, unresolved=0)
    memo = {}

    # Which function (if any) is line idx inside -- needed so an
    # interprocedurally-resolved bare identifier can be traced from
    # the RIGHT starting scope (its own enclosing function).
    enclosing = {}
    for name, d in function_defs.items():
        if d["file"] != path:
            continue
        for i in range(d["start"], d["end"] + 1):
            enclosing[i] = name

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
                continue  # multi-line call, out of scope (none exist today)
            args = split_top_level_args(line[open_paren + 1:close_paren])
            if not args:
                continue
            stats["total_calls"] += 1
            func_name = enclosing.get(idx)
            floor_idx = function_defs[func_name]["start"] if func_name else 0

            accessor = resolve_accessor(args[0], buffers)
            candidates = {}  # accessor -> severity
            if accessor:
                stats["resolved_direct"] += 1
                candidates[accessor] = "DEFINITE"
            else:
                a0 = strip_casts(args[0])
                if func_name and IDENT_ONLY_RE.match(a0):
                    resolved = resolve_expr(a0, func_name, idx, function_defs, buffers, call_sites, 0, memo, set())
                    if resolved:
                        stats["resolved_indirect"] += 1
                        for acc in resolved:
                            candidates[acc] = "REVIEW"
                    else:
                        stats["unresolved"] += 1
                else:
                    stats["unresolved"] += 1

            for acc, base_severity in candidates.items():
                size, capacity, cpath = buffers[acc]
                if fn == "buf_checksum":
                    if len(args) < 3:
                        continue
                    start_v = eval_closed_arith(args[1])
                    len_v = eval_closed_arith(args[2])
                    if start_v is None or len_v is None:
                        continue
                    end = start_v + len_v
                    if end > capacity:
                        sev = base_severity if base_severity == "REVIEW" else "DEFINITE"
                        findings.append(dict(
                            severity=sev, file=path, line=idx + 1,
                            msg=(f"buf_checksum(({acc}), start={start_v}, "
                                 f"len={len_v}) touches byte {end - 1}, but "
                                 f"{acc}'s physical capacity is only "
                                 f"{capacity} bytes (declared size {size})"
                                 + ("" if base_severity == "DEFINITE" else
                                    f" -- REVIEW: {acc} reached via interprocedural"
                                    f" buffer-identity tracing, not a direct call"))))
                    continue

                width = BUF_FN_WIDTH[fn]
                f = check_offset(fn, args[1], width, capacity, size, acc, lines, idx, base_severity, floor_idx)
                if f is not None:
                    if base_severity == "REVIEW" and f["severity"] == "DEFINITE":
                        f["severity"] = "REVIEW"
                        f["msg"] += (f" -- REVIEW: {acc} reached via interprocedural"
                                     f" buffer-identity tracing, not a direct call")
                    f["file"] = path
                    findings.append(f)

    return findings, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime-dir", default=os.path.join(os.path.dirname(__file__), "..", "runtime"))
    ap.add_argument("--src-dir", default=os.path.join(os.path.dirname(__file__), "..", "src"))
    ap.add_argument("--log-level", default="WARNING",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     help="DEBUG shows every buffer-identity resolution step "
                          "(call sites visited, locals traced, recursion-guard "
                          "hits, unresolved leaves) -- use it to debug why a "
                          "call site did or didn't resolve.")
    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(message)s")

    buffers = parse_c_scratch_buffers(args.runtime_dir)
    if not buffers:
        print(f"WARNING: no SCRATCH_BUF/SCRATCH_BUF_PTR accessors found under {args.runtime_dir}")

    vani_files = sorted(glob.glob(os.path.join(args.src_dir, "*.vani")))
    function_defs = parse_function_defs(vani_files)
    call_sites = parse_call_sites(function_defs)

    all_findings = []
    totals = dict(total_calls=0, resolved_direct=0, resolved_indirect=0, unresolved=0)
    for path in vani_files:
        findings, stats = scan_vani_file(path, buffers, function_defs, call_sites)
        all_findings.extend(findings)
        for k in totals:
            totals[k] += stats[k]

    print(f"Parsed {len(buffers)} scratch-buffer accessors from {args.runtime_dir}.")
    print(f"Parsed {len(function_defs)} function definitions, "
          f"{sum(len(v) for v in call_sites.values())} call sites, "
          f"from {len(vani_files)} .vani files under {args.src_dir}.")
    print(f"Buffer-access call sites: {totals['total_calls']} total -- "
          f"{totals['resolved_direct']} direct, "
          f"{totals['resolved_indirect']} resolved interprocedurally, "
          f"{totals['unresolved']} unresolved (documented gap; "
          f"--log-level=DEBUG to see why).")

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
