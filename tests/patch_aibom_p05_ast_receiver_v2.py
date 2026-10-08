from pathlib import Path
import ast

TARGET = Path(r".\scanner\aibom.py")

text = TARGET.read_text(encoding="utf-8-sig")

old = r'''    # ------------------------------------------------------------------
    # Build receiver -> ALL model calls.
    # ------------------------------------------------------------------
    receiver_calls = {}

    for line_no, resolution in model_calls.items():
        if not (1 <= line_no <= len(lines)):
            continue

        start_line = max(0, line_no - 8)
        context = "\n".join(lines[start_line:line_no])

        match = re.search(
            r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\(',
            context,
        )

        if match:
            receiver = match.group(1)

            receiver_calls.setdefault(receiver, []).append(
                (line_no, resolution)
            )
'''

new = r'''    # ------------------------------------------------------------------
    # Build receiver -> ALL model calls using AST structure.
    #
    # Do not infer the receiver from source-text regex because a bounded
    # context may contain constructor/import calls before the actual API
    # call. For example:
    #
    #   client = OpenAI()
    #   response = client.chat.completions.create(
    #       model="gpt-5"
    #
    # The receiver is structurally "client", not "OpenAI".
    # ------------------------------------------------------------------
    receiver_calls = {}

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Only process calls that actually contain a model keyword
            # represented by the model-call extractor.
            if not any(
                keyword.arg in _AIBOM_MODEL_KEYWORDS
                for keyword in node.keywords
            ):
                continue

            line_no = getattr(node, "lineno", None)
            resolution = model_calls.get(line_no)

            if not resolution:
                continue

            receiver = None
            func = node.func

            # Walk Attribute(value=..., attr=...) down to the root.
            # Example:
            #   client.chat.completions.create(...)
            #
            # root = Name("client")
            while isinstance(func, ast.Attribute):
                func = func.value

            if isinstance(func, ast.Name):
                receiver = func.id

            if receiver:
                receiver_calls.setdefault(receiver, []).append(
                    (line_no, resolution)
                )
'''

if old not in text:
    print("[ERROR] Existing regex receiver block not found.")
    raise SystemExit(1)

backup = TARGET.with_suffix(TARGET.suffix + ".bak_p05_receiver")

if not backup.exists():
    backup.write_text(text, encoding="utf-8")

text = text.replace(old, new, 1)

TARGET.write_text(text, encoding="utf-8")

print("[PASS] Structural AST receiver association patch applied")
print(f"[BACKUP] {backup}")
