from pathlib import Path

path = Path(r".\scanner\aibom.py")
text = path.read_text(encoding="utf-8-sig")

old = '''    receiver_calls = {}

    for line_no, resolution in model_calls.items():
        if not (1 <= line_no <= len(lines)):
            continue

        # Search backwards to the call expression.
        start = max(0, line_no - 6)
        context = "\\n".join(lines[start:line_no])

        match = re.search(
            r'\\b([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*\\s*\\(',
            context,
        )

        if match:
            receiver = match.group(1)
            receiver_calls.setdefault(receiver, []).append(
                (line_no, resolution)
            )
'''

new = '''    receiver_calls = {}

    # Build receiver -> ALL model calls using the AST rather than a
    # backward text regex. This avoids mistaking an earlier constructor
    # such as ``client = OpenAI()`` for the receiver of a later call.
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            model_keyword = next(
                (
                    keyword
                    for keyword in node.keywords
                    if keyword.arg in _AIBOM_MODEL_KEYWORDS
                ),
                None,
            )

            if model_keyword is None:
                continue

            line_no = getattr(node, "lineno", None)
            if line_no not in model_calls:
                continue

            receiver = node.func

            # Resolve Attribute chains such as:
            # client.chat.completions.create(...)
            # to the root Name:
            # client
            while isinstance(receiver, ast.Attribute):
                receiver = receiver.value

            if isinstance(receiver, ast.Name):
                receiver_name = receiver.id
                receiver_calls.setdefault(
                    receiver_name,
                    [],
                ).append(
                    (line_no, model_calls[line_no])
                )
'''

if old not in text:
    raise SystemExit("[ERROR] Existing receiver construction block not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")

print("[PASS] AST receiver association patch applied")
