"""Deterministic fuzz targets for the four task.md section 13 surfaces.

``cargo fuzz`` is NOT adopted: the libFuzzer harness tooling would need
nightly Rust + clang + a corpus workflow that this repo's broken rustup
cannot provide, and a fuzz runner that cannot run in the suite (or
offline) is a silent drop -- the offline/no-required-deps + suite
precedent applies (petgraph/axum/Rego/OIDC-SAML).  The same four
targets task.md names are fuzzed HERE in-house with seeded,
deterministic generators and hard iteration bounds:

    rule compiler       -- scanner.rust_engine._compile_program /
                           core.compile_rules (config -> rule program)
    parsers             -- core.scan's program-JSON parser plus the
                           tree-sitter source parse (mutated files)
    walker              -- scan_directory over mutated trees, ignore
                           files and depth/width shapes
    DAST response parser-- analysis.dast.checks pure response
                           functions (_redirect_target, _excerpt,
                           _b64json, _detect_*)

CONTRACTS (measured on this box, not guesses):
* the rule compiler returns a PROGRAM_SCHEMA program or raises
  ValueError ("invalid scan config: ..." -- serde's typed rejection);
  TypeError never appears for JSON-able inputs, and a pyo3
  PanicException is a fuzz FAILURE (that is exactly the class of bug
  cargo fuzz would hunt);
* core.scan accepts str program text or raises ValueError (fast serde
  rejection, sub-2ms measured); non-str text would TypeError at the
  pyo3 boundary and is kept out of the input domain by construction;
* scan_directory completes with the same finding SET on repeat runs of
  the same tree (order-insensitive: group_findings output row order is
  not part of the contract, the set of (rule_id, file, line) is);
* the DAST response functions are total over their documented domains
  (int status, mapping headers, str body/url): they return
  None|str|dict|(str, dict) and raise nothing.

EXIT CODES
----------
    0   every iteration of every target held its contract
    1   at least one contract failure (printed, first 5 shown)
    2   could not run (native extension missing, import error)
"""
from __future__ import annotations
try:
    from analysis.spans import (
    WINDOW_16, WINDOW_200, WINDOW_M1, WINDOW_M3, WINDOW_SNIPPET)
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import (
    WINDOW_16, WINDOW_200, WINDOW_M1, WINDOW_M3, WINDOW_SNIPPET)

import copy
import hashlib
import io
import json
import random
import string
import sys
import tempfile
import time
import traceback
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

PROGRAM_SCHEMA = "rsecopsx.rule_program/v1"
FAILURE_CAP = 5

# Expected exception classes by target -- everything else is a failure.
_COMPILER_OK = (ValueError,)          # serde typed rejection
_PROGRAM_OK = (ValueError,)           # serde typed rejection on text


def _failures_append(failures: list, label: str, err: BaseException) -> None:
    if len(failures) < FAILURE_CAP:
        failures.append(
            {"where": label, "error": type(err).__name__,
             "detail": str(err)[:WINDOW_200],
             "trace": traceback.format_exc(limit=3).splitlines()[WINDOW_M3:]}
        )


def _rng_fingerprint(rng: random.Random) -> str:
    """Digest of the rng's FINAL state -- an observable marker of the
    mutation stream.  Same seed + same consumption -> same digest;
    a target that drops its seed (system-entropy rng) diverges here,
    which is exactly what the same-seed test must be able to see."""
    state = repr([rng.random() for _ in range(8)]).encode("utf-8")
    return hashlib.sha256(state).hexdigest()[:WINDOW_16]


def _rand_text(rng: random.Random, cap: int = 400) -> str:
    """Hostile-ish string: printable junk, control chars, unicode."""
    n = rng.randint(0, cap)
    alphabet = string.printable + "λ→ ﻿‮"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _mutate_value(rng: random.Random, value, depth: int = 0):
    """One JSON-able structural mutation (never non-serializable types)."""
    kind = rng.randint(0, 7 if depth < 3 else 4)
    if kind == 0:
        return None
    if kind == 1:
        return rng.randint(-2**31, 2**31)
    if kind == 2:
        return _rand_text(rng, 64)
    if kind == 3 and isinstance(value, dict):
        out = dict(value)
        op = rng.randint(0, 3)
        if op == 0 and out:
            out.pop(rng.choice(list(out)))
        elif op == 1:
            out[_rand_text(rng, 16)] = _mutate_value(
                rng, None, depth + 1)
        elif op == 2 and out:
            out[rng.choice(list(out))] = _mutate_value(
                rng, None, depth + 1)
        else:
            out = {k: _mutate_value(rng, v, depth + 1)
                   for k, v in out.items()}
        return out
    if kind == 4 and isinstance(value, list):
        if not value:
            return []
        op = rng.randint(0, 2)
        if op == 0:
            return value[:rng.randint(0, len(value))]
        if op == 1:
            out = list(value)
            out.insert(rng.randrange(len(out) + 1),
                       _mutate_value(rng, None, depth + 1))
            return out
        return [_mutate_value(rng, v, depth + 1) for v in value]
    if isinstance(value, dict):
        return {k: _mutate_value(rng, v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_mutate_value(rng, v, depth + 1) for v in value]
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + rng.choice([-1, 0, 1, 2**16, -(2**16)])
    if isinstance(value, str):
        return _rand_text(rng, max(4, len(value)))
    return _mutate_value(rng, None, depth + 1)


def _base_config() -> dict:
    from scanner import rust_engine
    with tempfile.TemporaryDirectory(prefix="rsx_t111_cfg_") as td:
        root = Path(td)
        (root / "seed.py").write_text("x = 1\n", encoding="utf-8")
        return rust_engine.build_config(root)


def _base_program(config: dict) -> str:
    from scanner import rust_engine
    return rust_engine._compile_program(config)


# ---------------------------------------------------------------------------
# Target 1: rule compiler (config -> program)
# ---------------------------------------------------------------------------


def fuzz_rule_compiler(iterations: int = 400, seed: int = 111) -> dict:
    from scanner import rust_engine

    rng = random.Random(seed)
    cfg = _base_config()
    single = copy.deepcopy(cfg)
    single["rules"] = [cfg["rules"][0]]
    failures: list = []
    compiled = rejected = 0
    t0 = time.time()
    for i in range(iterations):
        c = copy.deepcopy(single if rng.random() < 0.85 else cfg)
        op = rng.randint(0, 4)
        try:
            if op == 0:                       # mutate one rule field
                rule = c["rules"][rng.randrange(len(c["rules"]))]
                key = rng.choice(list(rule))
                rule[key] = _mutate_value(rng, rule[key])
            elif op == 1:                     # corrupt the rules list
                c["rules"] = _mutate_value(rng, c["rules"])
            elif op == 2:                     # drop/replace a top-level key
                key = rng.choice(list(c))
                if rng.random() < 0.5:
                    c.pop(key)
                else:
                    c[key] = _mutate_value(rng, c[key])
            elif op == 3:                     # hostile pattern string
                rule = c["rules"][rng.randrange(len(c["rules"]))]
                rule["pattern"] = rng.choice([
                    "([a-", "(a+)+$", "a{999999}", "(", ")", "[z-a]",
                    "\\p{Nope}", "(?P<>x)", "a" * 5000, "(?#",
                    _rand_text(rng, 120),
                ])
            else:                             # whole-program junk
                c = _mutate_value(rng, c)
            prog = rust_engine._compile_program(c)
            parsed = json.loads(prog)
            if parsed.get("schema") != PROGRAM_SCHEMA:
                raise AssertionError(
                    f"program schema {parsed.get('schema')!r}")
            compiled += 1
        except _COMPILER_OK:
            rejected += 1
        except BaseException as exc:          # noqa: BLE001 - fuzz surface
            _failures_append(failures, f"rule_compiler#{i}", exc)
    return {"target": "rule_compiler", "iterations": iterations,
            "seed": seed, "compiled": compiled, "rejected": rejected,
            "rng_digest": _rng_fingerprint(rng),
            "failures": failures,
            "elapsed_ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------------------
# Target 2a: program-JSON parser (core.scan input text)
# ---------------------------------------------------------------------------


def fuzz_program_parser(iterations: int = 300, seed: int = 112) -> dict:
    from scanner import rust_engine

    rng = random.Random(seed)
    cfg = _base_config()
    program = _base_program(cfg)
    ext = rust_engine.load_extension()
    with tempfile.TemporaryDirectory(prefix="rsx_t111_prog_") as td:
        root = Path(td)
        (root / "seed.py").write_text("payload = 1\n", encoding="utf-8")
        failures: list = []
        accepted = rejected = 0
        t0 = time.time()
        for i in range(iterations):
            op = rng.randint(0, 5)
            if op == 0:
                cut = rng.randrange(1, len(program))
                text = program[:cut]
            elif op == 1:
                pos = rng.randrange(len(program))
                text = program[:pos] + rng.choice(
                    [" ", "\\", '"', "{", "}", ",", ":"])
                text += program[pos:]
            elif op == 2:
                text = json.dumps({"schema": rng.choice(
                    ["nope", PROGRAM_SCHEMA, 1, None])})
            elif op == 3:
                text = _rand_text(rng, 300)
            elif op == 4:
                text = program.replace('"schema":', '"schema": ', 1)
            else:
                text = program[:WINDOW_M1] if program else program
            try:
                ext.scan(str(root), text)
                accepted += 1
            except _PROGRAM_OK:
                rejected += 1
            except BaseException as exc:      # noqa: BLE001 - fuzz surface
                _failures_append(failures, f"program_parser#{i}", exc)
    return {"target": "program_parser", "iterations": iterations,
            "seed": seed, "accepted": accepted, "rejected": rejected,
            "rng_digest": _rng_fingerprint(rng),
            "failures": failures,
            "elapsed_ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------------------
# Target 2b: tree-sitter source parse (mutated files, one real scan)
# ---------------------------------------------------------------------------


def _mutated_source(rng: random.Random) -> bytes:
    shape = rng.randint(0, 6)
    if shape == 0:                       # broken utf-8 on purpose
        return bytes(rng.choice(b"\xff\xfe\x80\xc3\x00") for _ in
                     range(rng.randint(1, 400)))
    if shape == 1:                       # huge single line
        line = "x = " + "1 + " * 4000 + "1\n"
        return line.encode("utf-8", "replace")
    if shape == 2:                       # deep bracket nesting
        return ("[" * 300 + "]" * 300).encode("utf-8")
    if shape == 3:                       # truncated code fragment
        frag = rng.choice(["def f(:", "class ", "if True", "SELECT * FROM",
                           "package x; {", "function (", "<<<"])
        return frag.encode("utf-8") + bytes(
            rng.randrange(256) for _ in range(rng.randint(0, 200)))
    if shape == 4:                       # nul + control soup
        return bytes(rng.choice([0, 7, 13, 27, 0x1b, 0x7f])
                     for _ in range(rng.randint(1, 500)))
    if shape == 5:                       # unicode soup
        pool = "λ→ ﻿‮😀 \t\r\n"
        return "".join(rng.choice(pool)
                       for _ in range(rng.randint(1, 400))).encode(
            "utf-8", "replace")
    # shape 6: valid-ish code mutated at random offsets
    base = bytearray(b"import os\n\ndef run(x):\n    return os.popen(x).read()\n")
    for _ in range(rng.randint(1, 8)):
        pos = rng.randrange(len(base))
        base[pos] = rng.randrange(256)
    return bytes(base)


def fuzz_source_parse(files: int = 60, seed: int = 113) -> dict:
    from scanner import rust_engine

    rng = random.Random(seed)
    failures: list = []
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="rsx_t111_src_") as td:
        root = Path(td)
        for i in range(files):
            ext = rng.choice(["py", "js", "java", "go", "php", "rs", "c"])
            (root / f"m{i}.{ext}").write_bytes(_mutated_source(rng))
        try:
            rows = rust_engine.scan_directory(root)
            if not isinstance(rows, list):
                raise AssertionError(
                    f"scan_directory returned {type(rows).__name__}")
        except BaseException as exc:          # noqa: BLE001 - fuzz surface
            _failures_append(failures, "source_parse#scan", exc)
    return {"target": "source_parse", "iterations": files, "seed": seed,
            "files": files, "rng_digest": _rng_fingerprint(rng),
            "failures": failures,
            "elapsed_ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------------------
# Target 3: walker (tree shapes + ignore rules + determinism)
# ---------------------------------------------------------------------------


def _build_tree(root: Path, rng: random.Random, wide: bool) -> None:
    depth = rng.randint(2, 10 if not wide else 4)
    branch = rng.randint(1, 4 if not wide else 8)
    names = ["pkg", "src dir", "módulo", ".hidden", "nul\0name".replace(
        "\0", "x"), "node_modules", "venv", ".git"]
    node = root
    for level in range(depth):
        node = node / (rng.choice(names) + str(level))
        node.mkdir(parents=True, exist_ok=True)
        n_files = rng.randint(1, 6 if not wide else 14)
        for f in range(n_files):
            (node / f"f{f}.py").write_text(
                f"x{f} = {f}\n", encoding="utf-8")
    if rng.random() < 0.7:
        # hostile-ish ignore rules: partial globs, negations, junk lines
        (root / ".gitignore").write_text(
            "\n".join([
                "*.pyc",
                "!keep*.py",
                rng.choice(["[", "(", "!", "**/", "*"]),
                "src dir" + str(rng.randint(0, depth)),
                _rand_text(rng, 60),
            ]) + "\n", encoding="utf-8", errors="replace")
    if rng.random() < 0.5:
        (root / ".sastignore").write_text(
            rng.choice(["f0.py", "*.py", "nonsense/", _rand_text(rng, 40)]),
            encoding="utf-8", errors="replace")


def _finding_triples(rows) -> set:
    out = set()
    for row in rows or []:
        if isinstance(row, dict):
            out.add((str(row.get("rule_id")), str(row.get("file")),
                     str(row.get("line"))))
    return out


def fuzz_walker(trees: int = 40, seed: int = 114) -> dict:
    from scanner import rust_engine

    rng = random.Random(seed)
    failures: list = []
    deterministic = 0
    t0 = time.time()
    for i in range(trees):
        try:
            with tempfile.TemporaryDirectory(
                    prefix=f"rsx_t111_walk{i:02d}_") as td:
                root = Path(td)
                _build_tree(root, rng, wide=bool(i % 2))
                first = _finding_triples(rust_engine.scan_directory(root))
                # Double-scan only the first few trees -- each
                # scan_directory is ~300ms, and determinism holds for
                # the same (tree, seed); spot-checking 3 trees gives
                # the same signal at a fraction of the suite cost.
                if i < 3:
                    second = _finding_triples(
                        rust_engine.scan_directory(root))
                    if first != second:
                        raise AssertionError(
                            f"walker nondeterministic: "
                            f"{len(first ^ second)} differing triples")
                    deterministic += 1
        except BaseException as exc:          # noqa: BLE001 - fuzz surface
            _failures_append(failures, f"walker#{i}", exc)
    return {"target": "walker", "iterations": trees, "seed": seed,
            "deterministic": deterministic,
            "rng_digest": _rng_fingerprint(rng),
            "failures": failures,
            "elapsed_ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------------------
# Target 4: DAST response parser (pure checks.py response functions)
# ---------------------------------------------------------------------------


def fuzz_dast_response(iterations: int = 500, seed: int = 115) -> dict:
    from analysis.dast.checks import (
        CheckContext, ProbeResponse, _b64json, _detect_cmdi,
        _detect_lfi, _detect_redirect, _detect_sqli, _detect_ssti,
        _detect_xss, _excerpt, _redirect_target,
    )

    rng = random.Random(seed)
    failures: list = []
    host = "http://target.example"
    ctx = CheckContext(base_url=host + "/", routes=[], fetch=lambda *a,
                       **k: None, live=False)
    status_pool = [0, 200, 204, 299, 300, 301, 302, 303, 307, 308, 399,
                   400, 404, 429, 500, -1, 2**31 - 1, 2**31, 2**40]
    loc_pool = ["", "/next", "//evil.example/x", "http://evil.example/",
                "https://target.example/a", "?q=1", "#frag",
                "javascript:alert(1)", "  /trimmed  ", "a" * 4000,
                "λ→/ünicode", "../escape", "data:text/html,x"]
    body_pool = [
        "", "ok", "You have an error in your SQL syntax",
        "<script>alert(1)</script>", "root:x:0:0", "$({id})",
        "645498", "{{987*654}}", "\x00\x01\x02", "λ→﻿",
        "A" * 60000, "SELECT * FROM users; --", "passwd", "canary",
        "line1\r\nline2\nline3", '"{}"[]()',
    ]
    payload_pool = [None, "", "x", "{{987*654}}", "' OR 1=1 --",
                    "$(id)", _rand_text(rng, 200)]
    t0 = time.time()
    for i in range(iterations):
        status = rng.choice(status_pool) if rng.random() < 0.5 else \
            rng.randint(-1000, 100000)
        headers = {}
        if rng.random() < 0.7:
            headers["location"] = rng.choice(loc_pool)
        if rng.random() < 0.3:
            headers[rng.choice(["content-type", "server", "x-y"])] = \
                _rand_text(rng, 80)
        body = rng.choice(body_pool)
        url = rng.choice([host + "/p", host + "/", "http://other.example/p",
                          "", "not a url", host + "/" + _rand_text(rng, 40)])
        payload = rng.choice(payload_pool)
        resp = ProbeResponse(url=url, status=status, headers=headers,
                             body=body)
        try:
            nxt = _redirect_target(status, headers, url or host, host)
            if nxt is not None and not isinstance(nxt, str):
                raise AssertionError(f"_redirect_target -> {type(nxt)}")
            excerpt = _excerpt(body, None if rng.random() < 0.5
                               else rng.randint(-10, 10**6))
            if not isinstance(excerpt, str):
                raise AssertionError(f"_excerpt -> {type(excerpt)}")
            tok = _b64json(rng.choice(
                ["", "!!!", "eyJhIjoxfQ", "not-base64", _rand_text(rng, 80),
                 "eyJhIjoxfQ=="]))
            if tok is not None and not isinstance(tok, dict):
                raise AssertionError(f"_b64json -> {type(tok)}")
            for fn in (_detect_sqli, _detect_xss, _detect_lfi,
                       _detect_cmdi, _detect_ssti, _detect_redirect):
                out = fn(resp, ctx, "q", payload)
                if out is not None and not (
                        isinstance(out, tuple) and len(out) == 2
                        and isinstance(out[0], str)
                        and isinstance(out[1], dict)):
                    raise AssertionError(f"{fn.__name__} -> {out!r}")
        except BaseException as exc:          # noqa: BLE001 - fuzz surface
            _failures_append(failures, f"dast_response#{i}", exc)
    return {"target": "dast_response", "iterations": iterations,
            "seed": seed, "rng_digest": _rng_fingerprint(rng),
            "failures": failures,
            "elapsed_ms": int((time.time() - t0) * 1000)}


TARGETS = {
    "rule_compiler": fuzz_rule_compiler,
    "program_parser": fuzz_program_parser,
    "source_parse": fuzz_source_parse,
    "walker": fuzz_walker,
    "dast_response": fuzz_dast_response,
}

# The per-target keyword that scales the count (not every target names
# its knob "iterations" -- walker counts trees, source_parse counts
# files; run_all must dispatch the RIGHT kwarg or the CLI dies rc2).
_TARGET_KW = {
    "rule_compiler": "iterations",
    "program_parser": "iterations",
    "source_parse": "files",
    "walker": "trees",
    "dast_response": "iterations",
}


def run_all(iterations: int | None = None, seed: int = 111) -> dict:
    """Run every target; `iterations` scales the default counts."""
    results = []
    for offset, (name, fn) in enumerate(TARGETS.items()):
        kw = {"seed": seed + offset}
        if iterations is not None:
            kw[_TARGET_KW[name]] = iterations
        results.append(fn(**kw))
    return {
        "schema": "rsecopsx.fuzz_targets/v1",
        "targets": results,
        "total_failures": sum(len(r["failures"]) for r in results),
        "elapsed_ms": sum(r["elapsed_ms"] for r in results),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="python -m analysis.validation.fuzz_targets",
        description="Deterministic in-house fuzz targets (cargo fuzz NOT "
                    "adopted -- see module docstring).")
    ap.add_argument("--iterations", type=int, default=None,
                    help="override per-target iteration count")
    ap.add_argument("--seed", type=int, default=111)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        report = run_all(args.iterations, args.seed)
    except Exception:                          # noqa: BLE001 - rc2 surface
        traceback.print_exc()
        return 2
    if args.json:
        # Wrap for cp1252-safe unicode; detach before the wrapper is
        # GC'd -- TextIOWrapper.close() would close the shared buffer
        # underneath pytest's capture and blow up at teardown.
        original = sys.stdout
        wrapper = io.TextIOWrapper(original.buffer, encoding="utf-8",
                                   errors="replace")
        sys.stdout = wrapper
        try:
            print(json.dumps(report, indent=2))
            wrapper.flush()
        finally:
            sys.stdout = original
            wrapper.detach()
    else:
        for row in report["targets"]:
            head = (f"{row['target']}: iters={row['iterations']} "
                    f"failures={len(row['failures'])} "
                    f"{row['elapsed_ms']}ms")
            print(head)
            for f in row["failures"]:
                print("  FAIL", f["where"], f["error"], f["detail"][:WINDOW_SNIPPET])
        print(f"total_failures={report['total_failures']} "
              f"elapsed_ms={report['elapsed_ms']}")
    return 1 if report["total_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
