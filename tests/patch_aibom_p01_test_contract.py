from pathlib import Path

p = Path(r".\tests\test_v11_aibom_p01_negative_matrix.py")

s = p.read_text(encoding="utf-8-sig")

old = '''        ast_rows = [
            row
            for row in rows
            if row.get("import_resolution")
            and (
                "AST" in (row.get("detection_mode") or "")
                or "AST" in (row.get("evidence_type") or [])
            )
        ]

        actual = len(ast_rows)

        print("AST/IMPORT FINDINGS =", actual)

        assert actual == expected_ast_count, (
            f"{name}: expected {expected_ast_count} "
            f"AST/import findings, got {actual}"
        )

        print("[PASS] AST/import expected behavior")
'''

new = '''        ast_rows = [
            row
            for row in rows
            if row.get("import_resolution")
        ]

        actual = len(ast_rows)

        print("AST/IMPORT FINDINGS =", actual)

        assert actual == expected_ast_count, (
            f"{name}: expected {expected_ast_count} "
            f"AST/import findings, got {actual}"
        )

        if expected_ast_count:
            for row in ast_rows:
                assert row.get("provider"), (
                    f"{name}: resolved finding missing provider"
                )
                assert row.get("component"), (
                    f"{name}: resolved finding missing component"
                )
                assert row.get("import_resolution"), (
                    f"{name}: resolved finding missing import_resolution"
                )

        print("[PASS] AST/import expected behavior")
'''

if old not in s:
    raise SystemExit("ERROR: Expected test block was not found. No change made.")

s = s.replace(old, new)

p.write_text(s, encoding="utf-8")

print("[PASS] Updated P0.1 test to use import_resolution contract")
