"""Phase 3.1 — parsed IaC object models behind the three IaC scanners.

WHAT THIS DELIVERS
------------------
Gap-plan row 3.1: the IaC engines matched raw lines with regex, so every
rule was really a question about line SHAPE. This module parses each
format into objects and lets rules ask questions about STRUCTURE:

* Terraform — HCL2 subset parser (``parse_hcl2``): block headers with
  labels, attributes with statically-known values, nested blocks, exact
  line numbers. Expressions the parser cannot evaluate (function calls,
  references, interpolations, heredocs) become the ``OPAQUE`` sentinel
  and are never claimed as evidence.
* Kubernetes — ``parse_k8s_documents`` builds YAML objects with a
  path -> line table from ``yaml.compose`` marks. PyYAML is OPTIONAL:
  when the package is absent the function returns ``None`` and the
  caller falls back to its regex engine (the stdlib-only posture holds).
* Dockerfile — ``parse_dockerfile`` yields instruction records with
  continuations joined and comment lines excluded.

WHY THIS IS MORE PRECISE (each pinned by tests/test_phase3_iac_models.py)
------------------------------------------------------------------------
Terraform:
* ingress vs egress — an egress block open to 0.0.0.0/0 (the AWS
  default) is NOT an ingress finding; the old line regex fired on both.
* resource-kind scoping — ``cidr_blocks`` in locals, modules or data
  sources is not a deployed security group.
* exact attribute names — ``storage_encrypted = false`` used to ALSO
  fire the ``encrypted = false`` rule (substring match), double-counting
  CWE-311 on every unencrypted RDS instance.
* IPv6 equality — ``2001:db8::/0`` CONTAINS the substring ``::/0``; the
  old regex called a scoped prefix "open to the world".
Kubernetes:
* ``valueFrom: secretKeyRef`` env vars are NOT hardcoded secrets — the
  old regex fired on the variable name alone.
* pod-level securityContext inheritance is read from the sibling of the
  containers key; the old regex grabbed the FIRST ``securityContext``
  block in the document, which is often a container's, letting one
  container's controls satisfy the next.
* ``- NET_RAW`` under ``drop:`` is a hardening step, not a finding —
  only ``capabilities.add`` counts.
Dockerfile:
* comment lines no longer fire content rules (``# curl ... | sh``).
* continuations are joined, so ``RUN curl ... \\`` on one line and
  ``| sh`` on the next is seen (previously a miss).

HONESTY CONTRACTS
-----------------
* OPAQUE means "cannot be evaluated statically" — never claimed, never
  guessed (``FROM ${BASE_IMAGE}`` fires no image rule; an sg rule whose
  ``type = var.x`` is not assumed to be ingress).
* Every parse has a fallback: ``parse_hcl2`` marks ``ok=False`` on
  unbalanced/malformed input and the YAML/Docker parsers return ``None``
  on failure; the calling scanner then runs its ORIGINAL regex engine
  for that file. Structure degrades to text, never to silence.
* Findings anchor where the corpus labels them: Terraform at the
  RESOURCE HEADER line (the old logical-unit start), Kubernetes at the
  exact key line, Dockerfile at the instruction line.
* Every structured finding carries ``resource_path`` — the gap-plan
  acceptance criterion ("IaC findings carry resource-path evidence").
* Nothing here rewrites severity: rule metadata comes from the caller's
  RULES tables, untouched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

try:  # PyYAML is optional; absence must not break the import chain.
    import yaml
    from yaml import nodes as _yn
except Exception:  # pragma: no cover - exercised via monkeypatch in tests
    yaml = None  # type: ignore[assignment]
    _yn = None  # type: ignore[assignment]


# Sentinel: a value the parser can see but not evaluate (function call,
# resource reference, interpolation, heredoc, object expression).
OPAQUE = object()

#: Kubernetes workload kinds whose documents the K8s rules apply to.
#: Single source of truth: iac_kubernetes imports it for both its legacy
#: regex path and this structured path.
WORKLOAD_KINDS = frozenset({
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
})


# ===========================================================================
# Terraform — HCL2 subset parser
# ===========================================================================

@dataclass
class HclAttribute:
    """One ``name = value`` assignment inside an HCL block."""

    name: str
    value: Any            # literal, list of literals (OPAQUE elements allowed), or OPAQUE
    raw: str
    line: int
    opaque: bool = False  # True when value == OPAQUE


@dataclass
class HclBlock:
    """A braced HCL block: resource/data headers and nested blocks alike."""

    kind: str                       # "resource" | "data" | "variable" | ... | "" (nested)
    type: str                       # resource/data type, nested block name, else ""
    labels: list[str]               # resource/data name labels; variable/output names
    attributes: dict[str, HclAttribute] = field(default_factory=dict)
    blocks: list["HclBlock"] = field(default_factory=list)
    line: int = 1
    end_line: int = 1

    @property
    def name(self) -> str:
        """The resource/data name label (labels exclude the type token)."""
        return self.labels[0] if self.labels else ""

    def walk(self) -> Iterator["HclBlock"]:
        """This block and every descendant, in document order."""
        yield self
        for child in self.blocks:
            yield from child.walk()

    def attrs_named(self, name: str) -> list[tuple["HclBlock", HclAttribute]]:
        """Every attribute with this exact name anywhere in the subtree."""
        return [
            (blk, attr)
            for blk in self.walk()
            for key, attr in blk.attributes.items()
            if key == name
        ]

    def attrs_named_any(self, names: frozenset[str]) -> list[tuple["HclBlock", HclAttribute]]:
        return [
            (blk, attr)
            for blk in self.walk()
            for key, attr in blk.attributes.items()
            if key in names
        ]


@dataclass
class ParsedHcl:
    blocks: list[HclBlock]
    ok: bool  # False -> caller must fall back to the regex engine


_HEADER_RE = re.compile(
    r"^(resource|data|variable|module|locals|provider|output|terraform"
    r"|moved|import|check)\b\s*(.*)$"
)
_ATTR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*)$")
_NESTED_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*(?:"[^"]*"\s*)*\{\s*$')
_HEREDOC_RE = re.compile(r'^<<-?\s*[\'"]?([A-Za-z_][A-Za-z0-9_]*)[\'"]?\s*$')
_DOUBLE_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
_SINGLE_RE = re.compile(r"^'((?:[^'\\]|\\.)*)'$")
_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_HEAD_TYPES = frozenset({"resource", "data"})


def _strip_hcl_comment(line: str) -> str:
    """Drop ``#``/``//`` comments, quote-aware (``"a#b"`` keeps its hash)."""
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                out.append(ch)
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            break
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _net_positive(text: str) -> bool:
    """True while any bracket group in ``text`` is still open (quote-aware)."""
    depth = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    quote: str | None = None
    esc = False
    for ch in text:
        if quote is not None:
            if esc:
                esc = False
                continue
            if ch == "\\" and quote == '"':
                esc = True
                continue
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in depth:
            depth[ch] += 1
        elif ch in closing:
            depth[closing[ch]] -= 1
    return any(v > 0 for v in depth.values())


def _split_top_level(text: str) -> list[str]:
    """Split a list body on commas that sit outside quotes/brackets."""
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    esc = False
    depth = 0
    for ch in text:
        if quote is not None:
            current.append(ch)
            if esc:
                esc = False
                continue
            if ch == "\\" and quote == '"':
                esc = True
                continue
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _classify_scalar(s: str) -> tuple[Any, bool]:
    """(value, opaque) for a scalar HCL expression."""
    m = _DOUBLE_RE.fullmatch(s)
    if m:
        body = m.group(1)
        if "${" in body:
            return OPAQUE, True
        return body, False
    m = _SINGLE_RE.fullmatch(s)
    if m:
        body = m.group(1)
        if "${" in body:
            return OPAQUE, True
        return body, False
    if s == "true":
        return True, False
    if s == "false":
        return False, False
    if _INT_RE.fullmatch(s):
        return int(s), False
    if _FLOAT_RE.fullmatch(s):
        return float(s), False
    return OPAQUE, True


def _classify_value(raw: str) -> tuple[Any, bool]:
    """Classify a consumed attribute value (possibly multi-line)."""
    s = raw.strip()
    if s.startswith("["):
        inner = s[1:]
        stripped = inner.rstrip()
        if not stripped.endswith("]"):
            return OPAQUE, True
        inner = stripped[:-1]
        elements: list[Any] = []
        for part in _split_top_level(inner):
            part = part.strip()
            if not part:
                continue
            if part.startswith(("[", "{")):
                elements.append(OPAQUE)
                continue
            value, _opaque = _classify_scalar(part)
            elements.append(value)
        return elements, False
    if s.startswith("{"):
        return OPAQUE, True
    return _classify_scalar(s)


def _parse_header_labels(rest: str) -> tuple[list[str], bool] | None:
    """Labels of a block header up to (and including) its ``{``.

    Returns ``(labels, inline_close)`` — ``inline_close`` is True for a
    single-line empty block (``data "x" "y" {}``), which ``terraform fmt``
    emits routinely and which must not unbalance the stack. Returns None
    when the line is malformed or carries no ``{``.
    """
    labels: list[str] = []
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':
            j = rest.find('"', i + 1)
            if j == -1:
                return None
            labels.append(rest[i + 1:j])
            i = j + 1
            continue
        if ch == "{":
            tail = rest[i + 1:].strip()
            return labels, tail.startswith("}")
        return None
    return None  # no { on this line


def parse_hcl2(source: str) -> ParsedHcl:
    """Tolerant line-oriented HCL2 subset parser.

    Malformed input (unclosed blocks, a top-level header inside an open
    block) yields ``ok=False``; the caller must then run its regex engine
    for this file. Never raises on user input.
    """
    lines = source.splitlines()
    blocks: list[HclBlock] = []
    stack: list[HclBlock] = []
    i = 0
    n = len(lines)

    while i < n:
        line_no = i + 1
        line = _strip_hcl_comment(lines[i]).strip()
        i += 1
        if not line:
            continue

        if line.startswith("}"):
            if stack:
                popped = stack.pop()
                popped.end_line = line_no
            continue

        attr_m = _ATTR_RE.match(line)
        if attr_m:
            name = attr_m.group(1)
            rest = attr_m.group(2)
            raw_value, i = _consume_value(lines, i, rest)
            value, opaque = _classify_value(raw_value)
            if stack:
                stack[-1].attributes[name] = HclAttribute(
                    name=name, value=value, raw=raw_value,
                    line=line_no, opaque=opaque,
                )
            continue

        head_m = _HEADER_RE.match(line)
        if head_m:
            if stack:
                # A top-level header while a block is still open means the
                # structure does not parse: degrade to the regex engine.
                return ParsedHcl(blocks, ok=False)
            kind = head_m.group(1)
            rest = head_m.group(2).strip()
            inline_close = False
            labels = _parse_header_labels(rest)
            if labels is not None:
                labels, inline_close = labels
            else:
                # ``{`` may sit on one of the next lines (rare formatting).
                labels, i = _header_next_lines(lines, i, rest)
                if labels is None:
                    return ParsedHcl(blocks, ok=False)
            block = HclBlock(
                kind=kind,
                type=labels[0] if kind in _HEAD_TYPES and labels else "",
                labels=labels[1:] if kind in _HEAD_TYPES and labels else labels,
                line=line_no,
                end_line=line_no,
            )
            blocks.append(block)
            if not inline_close:
                stack.append(block)
            continue

        nested_m = _NESTED_RE.match(line)
        if nested_m and stack:
            name = nested_m.group(1)
            # _NESTED_RE requires the line to END with ``{`` — an inline
            # empty block (``ingress {}``) never matches and is skipped.
            parsed_labels = _parse_header_labels(line[nested_m.end(1):])
            labels = parsed_labels[0] if parsed_labels else []
            block = HclBlock(
                kind="",
                type=name,
                labels=labels or [],
                line=line_no,
                end_line=line_no,
            )
            stack[-1].blocks.append(block)
            stack.append(block)
            continue

        # Anything else: stray token inside a block (e.g. a multi-line
        # string's tail) — ignored, matching how little it can affect.
        if not stack:
            # A stray top-level statement that is neither header nor
            # attribute is junk the regex engine gets to see instead.
            if _looks_malformed_top(line):
                return ParsedHcl(blocks, ok=False)

    if stack:
        return ParsedHcl(blocks, ok=False)
    return ParsedHcl(blocks, ok=True)


def _looks_malformed_top(line: str) -> bool:
    """Top-level junk that is more likely broken structure than content."""
    return bool(re.match(r'^[A-Za-z_][\w-]*\s+"', line))


def _header_next_lines(
    lines: list[str], i: int, rest: str,
) -> tuple[list[str] | None, int]:
    """Find a header's ``{`` on the following lines (bounded lookahead)."""
    parsed = _parse_header_labels(rest + " {")
    if parsed is None:
        return None, i
    labels = parsed[0]
    probe = i
    consumed = 0
    while probe < len(lines) and consumed < 3:
        candidate = _strip_hcl_comment(lines[probe]).strip()
        probe += 1
        consumed += 1
        if not candidate:
            continue
        if candidate == "{":
            return labels, probe
        return None, i
    return None, i


def _consume_value(lines: list[str], i: int, first: str) -> tuple[str, int]:
    """Consume a value that spans lines (balanced brackets or heredoc)."""
    parts = [first]
    s = first.strip()
    heredoc = _HEREDOC_RE.match(s)
    if heredoc:
        term = heredoc.group(1)
        while i < len(lines):
            part = lines[i]
            i += 1
            parts.append(part)
            stripped = part.strip()
            if stripped == term or stripped == "-" + term:
                break
        return "\n".join(parts), i
    while i < len(lines) and _net_positive("\n".join(parts)):
        parts.append(lines[i])
        i += 1
    return "\n".join(parts), i


# ===========================================================================
# Kubernetes — YAML documents with path -> line marks
# ===========================================================================

@dataclass
class K8sDocument:
    kind: str
    data: dict
    lines: dict[tuple, int]  # path tuple -> 1-based source line


def parse_k8s_documents(source: str) -> list[K8sDocument] | None:
    """Compose YAML into objects plus a path -> line table.

    Returns ``None`` on any failure (PyYAML absent, invalid YAML, a
    conversion error) so the caller falls back to its regex engine.
    """
    if yaml is None:
        return None
    try:
        composed = list(yaml.compose_all(source))
    except Exception:
        return None
    docs: list[K8sDocument] = []
    memo: dict[str, Any] = {}
    for node in composed:
        if node is None:
            continue
        lines_map: dict[tuple, int] = {}
        try:
            data = _node_to_obj(node, memo, lines_map, ())
        except Exception:
            return None
        if isinstance(data, dict):
            kind = data.get("kind")
            docs.append(K8sDocument(
                kind=kind if isinstance(kind, str) else "",
                data=data,
                lines=lines_map,
            ))
    return docs


def _node_to_obj(node: Any, memo: dict, lines: dict, path: tuple) -> Any:
    # id()-keyed memo: PyYAML resolves aliases to the SAME node object
    # (there is no AliasNode type), so a hit means an anchor reference —
    # returning the already-built object keeps shared structure shared.
    # The memo entry is written BEFORE recursing, which also breaks
    # cyclic anchors instead of recursing forever.
    marker = id(node)
    if marker in memo:
        return memo[marker]
    if isinstance(node, _yn.ScalarNode):
        value = _scalar_value(node)
        memo[marker] = value
        return value
    if isinstance(node, _yn.SequenceNode):
        items = []
        memo[marker] = items
        for idx, child in enumerate(node.value):
            items.append(_node_to_obj(child, memo, lines, path + (idx,)))
            lines[path + (idx,)] = child.start_mark.line + 1
        return items
    if isinstance(node, _yn.MappingNode):
        out: dict = {}
        memo[marker] = out
        for key_node, value_node in node.value:
            if not isinstance(key_node, _yn.ScalarNode):
                continue
            key = _scalar_value(key_node)
            out[key] = _node_to_obj(value_node, memo, lines, path + (key,))
            lines[path + (key,)] = key_node.start_mark.line + 1
        return out
    return None


def _scalar_value(node: Any) -> Any:
    raw = node.value
    tag = node.tag
    if tag == "tag:yaml.org,2002:bool":
        return str(raw).lower() in ("true", "yes", "on")
    if tag == "tag:yaml.org,2002:int":
        try:
            return int(raw, 0)
        except (TypeError, ValueError):
            return raw
    if tag == "tag:yaml.org,2002:float":
        try:
            return float(raw)
        except (TypeError, ValueError):
            return raw
    if tag == "tag:yaml.org,2002:null":
        return None
    return raw


def _walk_dicts(obj: Any, path: tuple = ()) -> Iterator[tuple[tuple, dict]]:
    if isinstance(obj, dict):
        yield path, obj
        for key, value in obj.items():
            yield from _walk_dicts(value, path + (key,))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            yield from _walk_dicts(value, path + (idx,))


def _walk_named_lists(obj: Any, names: frozenset[str], path: tuple = ()) -> Iterator[tuple[tuple, list]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = path + (key,)
            if key in names and isinstance(value, list):
                yield child, value
            yield from _walk_named_lists(value, names, child)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            yield from _walk_named_lists(value, names, path + (idx,))


def _get_at(obj: Any, path: tuple) -> Any:
    current = obj
    for part in path:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and isinstance(part, int) and part < len(current):
            current = current[part]
        else:
            return None
        if current is None:
            return None
    return current


def _fmt_path(path: tuple) -> str:
    out = ""
    first = True
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            if not first:
                out += "."
            out += str(part)
            first = False
    return out


def _is_zero_uid(value: Any) -> bool:
    # int 0 is the root uid; the string form ("0") is also written and is
    # still root — the old text regex only caught the unquoted int.
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, str):
        return value.strip() == "0"
    return False


def _image_is_latest(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    ref = value.strip()
    if "@" in ref:  # digest-pinned: no tag to be "latest"
        return False
    tail = ref.rsplit("/", 1)[-1]
    if ":" not in tail:
        return False
    return tail.rsplit(":", 1)[-1].lower() == "latest"


# (key, rule_id, predicate) — value rules applied to every mapping in a
# workload document, mirroring the breadth of the old line regex while
# reading parsed values instead of line shapes.
_K8S_KEY_RULES: tuple[tuple[str, str, Callable[[Any], bool]], ...] = (
    ("hostNetwork", "K8S_HOST_NETWORK", lambda v: v is True),
    ("hostPID", "K8S_HOST_PID", lambda v: v is True),
    ("hostIPC", "K8S_HOST_IPC", lambda v: v is True),
    ("privileged", "K8S_PRIVILEGED_CONTAINER", lambda v: v is True),
    ("allowPrivilegeEscalation", "K8S_ALLOW_PRIVILEGE_ESCALATION",
     lambda v: v is True),
    ("runAsUser", "K8S_RUN_AS_ROOT", _is_zero_uid),
    ("readOnlyRootFilesystem", "K8S_READ_ONLY_ROOT_FS_DISABLED",
     lambda v: v is False),
    ("imagePullPolicy", "K8S_IMAGE_PULL_ALWAYS",
     lambda v: isinstance(v, str) and v == "Always"),
    ("image", "K8S_LATEST_IMAGE_TAG", _image_is_latest),
)

_K8S_ENV_RULES: tuple[tuple[str, str], ...] = (
    (r"POSTGRES_PASSWORD|PGPASSWORD", "K8S_POSTGRES_PASSWORD_ENV"),
    (r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY", "K8S_AWS_SECRET_ENV"),
)

_K8S_NET_RAW = "K8S_NET_RAW_CAPABILITY"


# ===========================================================================
# Dockerfile — instruction records
# ===========================================================================

@dataclass
class DockerInstruction:
    op: str        # upper-cased instruction name
    args: str      # continuations joined, comments dropped
    line: int      # 1-based line of the instruction's first physical line
    raw: str       # first physical line, untouched


_INSTR_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*(.*)$")


def parse_dockerfile(source: str) -> list[DockerInstruction] | None:
    """Parse a Dockerfile into instruction records.

    Returns ``None`` only on an unexpected internal failure, which
    signals the caller to fall back to its regex engine. Comment-only
    files legitimately parse to ``[]``.
    """
    try:
        lines = source.splitlines()
        instructions: list[DockerInstruction] = []
        i = 0
        n = len(lines)
        while i < n:
            raw = lines[i]
            line_no = i + 1
            i += 1
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _INSTR_RE.match(raw.lstrip())
            if not match:
                continue  # stray continuation fragment
            op = match.group(1).upper()
            args = match.group(2)
            # Join backslash continuations; blank and comment lines inside
            # a continuation are skipped the way the builder skips them.
            while True:
                acc = args.rstrip()
                if not acc.endswith("\\"):
                    args = acc
                    break
                args = acc[:-1].rstrip() + " "
                while i < n and (
                    not lines[i].strip() or lines[i].strip().startswith("#")
                ):
                    i += 1
                if i >= n:
                    break
                args += lines[i].strip()
                i += 1
            instructions.append(DockerInstruction(
                op=op, args=args.strip(), line=line_no, raw=raw,
            ))
        return instructions
    except Exception:
        return None


# ===========================================================================
# Structured rule evaluation — Terraform
# ===========================================================================

_SG_RESOURCE_TYPES = frozenset({"aws_security_group", "aws_default_security_group"})
_PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})
_BPA_FLAGS = frozenset({
    "block_public_acls", "block_public_policy",
    "ignore_public_acls", "restrict_public_buckets",
})


def _list_contains(value: Any, target: str) -> bool:
    return isinstance(value, list) and any(
        isinstance(el, str) and el == target for el in value
    )


def _is_ingress_block(block: HclBlock) -> bool:
    if block.type == "ingress":
        return True
    # dynamic "ingress" { content { ... } } — same semantics, and the
    # egress twin must stay excluded.
    return block.type == "dynamic" and bool(block.labels) and block.labels[0] == "ingress"


def _sg_open(rule, resources, add, attr_name: str, target: str) -> None:
    rid = rule["rule_id"]
    for res in resources:
        name = res.name
        if res.type in _SG_RESOURCE_TYPES:
            for block in res.blocks:
                if not _is_ingress_block(block):
                    continue
                for _owner, attr in block.attrs_named(attr_name):
                    if _list_contains(attr.value, target):
                        add(rid, res.line,
                            f"resource.{res.type}.{name}.ingress.{attr.name}",
                            attr.line)
        elif res.type == "aws_security_group_rule":
            type_attr = res.attributes.get("type")
            if type_attr is None or type_attr.opaque:
                continue
            if not isinstance(type_attr.value, str):
                continue
            if type_attr.value.lower() != "ingress":
                continue
            for _owner, attr in res.attrs_named(attr_name):
                if _list_contains(attr.value, target):
                    add(rid, res.line,
                        f"resource.{res.type}.{name}.{attr.name}", attr.line)
        elif res.type == "aws_vpc_security_group_ingress_rule":
            for _owner, attr in res.attrs_named(attr_name):
                if _list_contains(attr.value, target):
                    add(rid, res.line,
                        f"resource.{res.type}.{name}.{attr.name}", attr.line)


def _tf_open_ingress(rule, resources, lines, add) -> None:
    _sg_open(rule, resources, add, "cidr_blocks", "0.0.0.0/0")


def _tf_open_ipv6(rule, resources, lines, add) -> None:
    _sg_open(rule, resources, add, "ipv6_cidr_blocks", "::/0")


def _tf_public_acl(rule, resources, lines, add) -> None:
    rid = rule["rule_id"]
    for res in resources:
        attr = res.attributes.get("acl")
        if attr is None or attr.opaque or not isinstance(attr.value, str):
            continue
        if attr.value.lower() in _PUBLIC_ACLS:
            add(rid, res.line, f"resource.{res.type}.{res.name}.acl", attr.line)


def _tf_block_public_access(rule, resources, lines, add) -> None:
    rid = rule["rule_id"]
    for res in resources:
        for _owner, attr in res.attrs_named_any(_BPA_FLAGS):
            if attr.value is False:
                add(rid, res.line,
                    f"resource.{res.type}.{res.name}.{attr.name}", attr.line)
                break  # one finding per resource (the unit-loop parity)


def _tf_unencrypted_bucket(rule, resources, lines, add) -> None:
    rid = rule["rule_id"]
    enc_resources = [
        res for res in resources
        if res.type == "aws_s3_bucket_server_side_encryption_configuration"
    ]
    enc_texts = [
        "\n".join(lines[max(res.line - 1, 0):res.end_line])
        for res in enc_resources
    ]
    for res in resources:
        if res.type != "aws_s3_bucket":
            continue
        if any(
            blk.type == "server_side_encryption_configuration"
            for blk in res.blocks
        ):
            continue  # encryption configured inline on the bucket
        name = res.name
        reference = f"aws_s3_bucket.{name}.id"
        if any(reference in text for text in enc_texts):
            continue  # a separate encryption config targets this bucket
        add(rid, res.line, f"resource.aws_s3_bucket.{name}", res.line)


def _tf_attr_is(rule, resources, add, attr_name: str, want: Any) -> None:
    rid = rule["rule_id"]
    for res in resources:
        for _owner, attr in res.attrs_named(attr_name):
            if attr.value is want:
                add(rid, res.line,
                    f"resource.{res.type}.{res.name}.{attr.name}", attr.line)
                break  # one per resource, exactly as one per unit before


def _tf_publicly_accessible(rule, resources, lines, add) -> None:
    _tf_attr_is(rule, resources, add, "publicly_accessible", True)


def _tf_storage_unencrypted(rule, resources, lines, add) -> None:
    _tf_attr_is(rule, resources, add, "storage_encrypted", False)


def _tf_ebs_unencrypted(rule, resources, lines, add) -> None:
    # Exact attribute name: "storage_encrypted = false" must NOT fire this
    # rule the way the old substring regex did.
    _tf_attr_is(rule, resources, add, "encrypted", False)


_TF_HANDLERS: dict[str, Callable] = {
    "TF_OPEN_SECURITY_GROUP_INGRESS": _tf_open_ingress,
    "TF_OPEN_IPV6_INGRESS": _tf_open_ipv6,
    "TF_PUBLIC_S3_ACL": _tf_public_acl,
    "TF_S3_BLOCK_PUBLIC_ACCESS_DISABLED": _tf_block_public_access,
    "TF_UNENCRYPTED_S3_BUCKET": _tf_unencrypted_bucket,
    "TF_RDS_PUBLICLY_ACCESSIBLE": _tf_publicly_accessible,
    "TF_RDS_STORAGE_NOT_ENCRYPTED": _tf_storage_unencrypted,
    "TF_EBS_ENCRYPTION_DISABLED": _tf_ebs_unencrypted,
}


def evaluate_terraform_rules(
    rules: list[dict], source: str, blocks: list[HclBlock],
) -> list[dict]:
    """Evaluate structured Terraform rules against parsed blocks.

    Returns match dicts: rule_id, line (the RESOURCE HEADER line — the
    corpus labels anchor there), snippet (the offending attribute line),
    resource_path. Deterministic: rule order, then document order.
    """
    lines = source.splitlines()
    matches: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def add(rule_id: str, block_line: int, path: str, snippet_line: int) -> None:
        key = (rule_id, block_line)
        if key in seen:
            return
        seen.add(key)
        snippet = ""
        if 1 <= snippet_line <= len(lines):
            snippet = lines[snippet_line - 1].strip()
        matches.append({
            "rule_id": rule_id,
            "line": block_line,
            "snippet": snippet,
            "resource_path": path,
        })

    resources = [block for block in blocks if block.kind == "resource"]
    for rule in rules:
        handler = _TF_HANDLERS.get(rule["rule_id"])
        if handler is not None:
            handler(rule, resources, lines, add)
    return matches


# ===========================================================================
# Structured rule evaluation — Kubernetes
# ===========================================================================

def evaluate_k8s_rules(
    rules: list[dict],
    missing_rules: list[dict],
    documents: list[K8sDocument],
    source: str,
) -> list[dict]:
    """Evaluate K8s rules against parsed documents.

    Value rules walk every mapping (the breadth of the old line regex);
    missing-controls rules walk ``containers`` lists only, with
    pod-level securityContext read from the SIBLING of the containers
    key — never from another container.
    """
    lines = source.splitlines()
    matches: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def add(rule_id: str, path: tuple, line: int) -> None:
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        snippet = ""
        if 1 <= line <= len(lines):
            snippet = lines[line - 1].strip()
        matches.append({
            "rule_id": rule_id,
            "line": line,
            "snippet": snippet,
            "resource_path": _fmt_path(path),
        })

    for doc in documents:
        if doc.kind not in WORKLOAD_KINDS:
            continue
        data = doc.data

        for path, mapping in _walk_dicts(data):
            for key, rule_id, test in _K8S_KEY_RULES:
                if key in mapping and test(mapping[key]):
                    add(rule_id, path + (key,), doc.lines.get(path + (key,), 1))

        # NET_RAW is only a finding under capabilities.add — dropping it
        # under capabilities.drop is hardening, not a misconfiguration.
        for path, mapping in _walk_dicts(data):
            capabilities = mapping.get("capabilities")
            if not isinstance(capabilities, dict):
                continue
            additions = capabilities.get("add")
            if not isinstance(additions, list):
                continue
            for idx, capability in enumerate(additions):
                if isinstance(capability, str) and capability.upper() == "NET_RAW":
                    cap_path = path + ("capabilities", "add", idx)
                    add(_K8S_NET_RAW, cap_path, doc.lines.get(cap_path, 1))

        # Env secrets: ONLY a literal ``value`` counts. A valueFrom
        # (secretKeyRef / configMapKeyRef) is the correct pattern and the
        # old regex fired on the name regardless.
        for env_path, entries in _walk_named_lists(data, frozenset({"env"})):
            for idx, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                if "value" not in entry:
                    continue
                name = entry.get("name")
                if not isinstance(name, str):
                    continue
                for pattern, rule_id in _K8S_ENV_RULES:
                    if re.search(pattern, name, re.IGNORECASE):
                        add(rule_id, env_path + (idx, "name"),
                            doc.lines.get(env_path + (idx, "name"), 1))

        # Missing controls, containers only (the scope the legacy engine
        # used — initContainers deliberately stay out of this question).
        for containers_path, containers in _walk_named_lists(
            data, frozenset({"containers"})
        ):
            if not isinstance(containers, list) or not containers:
                continue
            pod_spec = _get_at(data, containers_path[:-1])
            pod_sc = (
                pod_spec.get("securityContext")
                if isinstance(pod_spec, dict) else None
            )
            if not isinstance(pod_sc, dict):
                pod_sc = {}
            for idx, container in enumerate(containers):
                if not isinstance(container, dict):
                    continue
                container_sc = container.get("securityContext")
                if not isinstance(container_sc, dict):
                    container_sc = {}
                item_path = containers_path + (idx,)
                item_line = doc.lines.get(item_path, 1)
                resources = container.get("resources")
                limits = (
                    resources.get("limits")
                    if isinstance(resources, dict) else None
                )
                for rule in missing_rules:
                    rule_id = rule["rule_id"]
                    if rule_id == "K8S_MISSING_RUN_AS_NON_ROOT":
                        satisfied = (
                            container_sc.get("runAsNonRoot") is True
                            or pod_sc.get("runAsNonRoot") is True
                        )
                    elif rule_id == "K8S_MISSING_READ_ONLY_ROOT_FS":
                        satisfied = (
                            container_sc.get("readOnlyRootFilesystem") is True
                            or pod_sc.get("readOnlyRootFilesystem") is True
                        )
                    elif rule_id == "K8S_MISSING_RESOURCE_LIMITS":
                        satisfied = isinstance(limits, dict) and (
                            "cpu" in limits or "memory" in limits
                        )
                    else:
                        continue  # unknown id: the caller owns that rule
                    if not satisfied:
                        add(rule_id, item_path, item_line)

    return matches


# ===========================================================================
# Structured rule evaluation — Dockerfile
# ===========================================================================

_SECRET_NAME_RE = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|SECRET_KEY",
    re.IGNORECASE,
)
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)
_SENSITIVE_PORTS = frozenset({22, 2375, 2376, 3306, 5432, 6379, 27017, 9200})


def _image_tail_has_tag(ref: str) -> str | None:
    tail = ref.rsplit("/", 1)[-1]
    if ":" not in tail:
        return None
    return tail.rsplit(":", 1)[-1]


def _from_image(args: str) -> str | None:
    tokens = [tok for tok in args.split() if not tok.startswith("--")]
    if not tokens:
        return None
    return tokens[0]


def _user_token(args: str) -> str:
    tokens = args.split()
    if not tokens:
        return ""
    return tokens[0].split(":")[0].lower()


def _user_is_root(args: str) -> bool:
    token = _user_token(args)
    return token in ("root", "0")


def _dk_runs_as_root(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op == "USER" and _user_is_root(ins.args):
            add(rid, ins.line, ctx(ins))


def _dk_missing_user(rid, instructions, ctx, add) -> None:
    users = [ins for ins in instructions if ins.op == "USER"]
    if any(not _user_is_root(ins.args) for ins in users):
        return
    froms = [ins for ins in instructions if ins.op == "FROM"]
    if not froms:
        return  # nothing to anchor to, exactly as the old FROM pattern
    add(rid, froms[0].line, ctx(froms[0]))


def _dk_latest_tag(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op != "FROM":
            continue
        ref = _from_image(ins.args)
        if ref and _image_tail_has_tag(ref) == "latest":
            add(rid, ins.line, ctx(ins))


def _dk_unpinned(rid, instructions, ctx, add) -> None:
    # Multi-stage builds: "FROM build AS publish" / "FROM prod as dev"
    # where the ref is a stage alias declared by an EARLIER FROM is not an
    # image reference at all -- the builder resolves it inside the file, so
    # tag/digest pinning is N/A and flagging it is a false positive (seen
    # on AgentGPT platform/Dockerfile:35 and autogen seed-memory/AgentHost).
    # Aliases match exactly, the way the builder resolves stage names, and
    # an instruction's OWN alias only enters the set after its ref is
    # judged, so "FROM a AS a" still flags the untagged image "a".
    stages: set[str] = set()
    for ins in instructions:
        if ins.op != "FROM":
            continue
        ref = _from_image(ins.args)
        tokens = [tok for tok in ins.args.split() if not tok.startswith("--")]
        alias = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else None

        resolved = ref is not None and ("@" in ref or "$" in ref
                                        or _image_tail_has_tag(ref) is not None)
        if ref and not resolved and ref not in stages:
            add(rid, ins.line, ctx(ins))
        if alias:
            stages.add(alias)


def _dk_add_remote(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op != "ADD":
            continue
        tokens = [tok for tok in ins.args.split() if not tok.startswith("--")]
        if tokens and tokens[0].startswith(("http://", "https://")):
            add(rid, ins.line, ctx(ins))


def _dk_env_secret(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op != "ENV":
            continue
        for token in ins.args.split():
            if "=" not in token:
                continue
            key = token.split("=", 1)[0]
            if _SECRET_NAME_RE.search(key):
                add(rid, ins.line, ctx(ins))
                break  # one finding per instruction (one per line before)


def _dk_arg_secret(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op == "ARG" and _SECRET_NAME_RE.search(ins.args):
            add(rid, ins.line, ctx(ins))


def _content_rule(pattern: str) -> Callable:
    rx = re.compile(pattern, re.IGNORECASE)

    def handler(rid, instructions, ctx, add) -> None:
        # Breadth parity with the old unanchored line regex (which also
        # saw ONBUILD RUN ...), minus comments and plus continuations.
        for ins in instructions:
            if rx.search(ins.args):
                add(rid, ins.line, ctx(ins))
    return handler


def _dk_aws_key(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if _AWS_KEY_RE.search(ins.args):
            add(rid, ins.line, ctx(ins))


def _dk_expose(rid, instructions, ctx, add) -> None:
    for ins in instructions:
        if ins.op != "EXPOSE":
            continue
        hit = False
        for token in ins.args.split():
            token = re.sub(r"/(tcp|udp)$", "", token.lower())
            if "-" in token:
                start, _sep, end = token.partition("-")
                if start.isdigit() and end.isdigit():
                    low, high = int(start), int(end)
                    if any(low <= port <= high for port in _SENSITIVE_PORTS):
                        hit = True
            elif token.isdigit() and int(token) in _SENSITIVE_PORTS:
                hit = True
        if hit:
            add(rid, ins.line, ctx(ins))


_DOCKER_HANDLERS: dict[str, Callable] = {
    "DOCKER_RUNS_AS_ROOT": _dk_runs_as_root,
    "DOCKER_MISSING_USER": _dk_missing_user,
    "DOCKER_LATEST_TAG": _dk_latest_tag,
    "DOCKER_UNPINNED_BASE_IMAGE": _dk_unpinned,
    "DOCKER_ADD_REMOTE_URL": _dk_add_remote,
    "DOCKER_CURL_PIPE_SHELL": _content_rule(
        r"(curl|wget).*(\|\s*(sh|bash|python|perl))"),
    "DOCKER_APT_GET_UPGRADE": _content_rule(r"apt(-get)?\s+upgrade"),
    "DOCKER_SECRETS_IN_ENV": _dk_env_secret,
    "DOCKER_SECRETS_IN_ARG": _dk_arg_secret,
    "DOCKER_AWS_KEY": _dk_aws_key,
    "DOCKER_SUDO_INSTALLED": _content_rule(
        r"(apt(-get)?|apk|yum|dnf)\s+.*install\s+.*\bsudo\b"),
    "DOCKER_SSH_SERVER": _content_rule(
        r"(apt(-get)?|apk|yum|dnf)\s+.*install\s+.*(openssh-server|ssh)"),
    "DOCKER_CHMOD_777": _content_rule(r"chmod\s+(-R\s+)?777\b"),
    "DOCKER_EXPOSE_SENSITIVE_PORT": _dk_expose,
}


def evaluate_docker_rules(
    rules: list[dict], instructions: list[DockerInstruction], source: str,
) -> list[dict]:
    """Evaluate Dockerfile rules against parsed instruction records."""
    lines = source.splitlines()
    matches: list[dict] = []
    seen: set[tuple[str, int]] = set()

    ordinals: dict[int, int] = {}
    counter: dict[str, int] = {}
    for ins in instructions:
        counter[ins.op] = counter.get(ins.op, 0) + 1
        ordinals[id(ins)] = counter[ins.op]

    def ctx(ins: DockerInstruction) -> str:
        return f"dockerfile.{ins.op.lower()}[{ordinals[id(ins)]}]"

    def add(rule_id: str, line: int, path: str) -> None:
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        snippet = ""
        if 1 <= line <= len(lines):
            snippet = lines[line - 1].strip()
        matches.append({
            "rule_id": rule_id,
            "line": line,
            "snippet": snippet,
            "resource_path": path,
        })

    for rule in rules:
        handler = _DOCKER_HANDLERS.get(rule["rule_id"])
        if handler is not None:
            handler(rule["rule_id"], instructions, ctx, add)
    return matches
