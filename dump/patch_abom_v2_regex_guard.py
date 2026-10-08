from pathlib import Path

p = Path(r"D:\Data\Code test\R-SecOpsX_V11\scanner\abom_v2.py")

s = p.read_text(encoding="utf-8-sig")

guard = r'''
def _regex_match_is_code(source, match_start):
    """Return False when a regex match occurs inside a Python string/comment."""
    import io
    import tokenize

    try:
        line_no = source.count("\n", 0, match_start) + 1
        line_start = source.rfind("\n", 0, match_start) + 1
        col_no = match_start - line_start

        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            tok_type = tok.type
            (sl, sc), (el, ec) = tok.start, tok.end

            if sl > line_no:
                break

            if tok_type not in (tokenize.STRING, tokenize.COMMENT):
                continue

            if sl <= line_no <= el:
                if sl == el:
                    if sl == line_no and sc <= col_no < ec:
                        return False
                elif line_no == sl and col_no >= sc:
                    return False
                elif sl < line_no < el:
                    return False
                elif line_no == el and col_no < ec:
                    return False

        return True

    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return True


'''

if "_regex_match_is_code(" not in s:
    # Insert immediately before the first scan function.
    candidates = [
        "def scan_file(",
        "def _scan_file(",
    ]

    marker = next((x for x in candidates if x in s), None)

    if marker is None:
        raise SystemExit("Could not locate scan_file() anchor.")

    s = s.replace(marker, guard + marker, 1)

p.write_text(s, encoding="utf-8")
print("[PASS] Guard inserted")
