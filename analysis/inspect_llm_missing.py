import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scanner.llm_security as llm

target = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

targets = {
    target / "juice-shop_20.2.0" / "routes" / "chat.ts": [200],
    target / "juice-shop_20.2.0" / "frontend" / "src" / "app" /
        "two-factor-auth" / "two-factor-auth.component.spec.ts":
        [49, 95, 106, 145, 185, 192, 202, 213, 222, 231, 243],
}

for filepath, wanted_lines in targets.items():
    print("\n" + "=" * 80)
    print("FILE:", filepath)
    print("=" * 80)

    text = filepath.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # Run the ORIGINAL scanner on the complete file.
    results = llm.scan_llm_file(str(filepath), text)

    for n in wanted_lines:
        line = lines[n - 1]

        print("\nLINE", n)
        print("TEXT:", line)

        matching = [
            r for r in results
            if r.get("line") == n
        ]

        if matching:
            for r in matching:
                print(
                    "MATCH:",
                    r.get("rule_id"),
                    "|",
                    r.get("title"),
                    "|",
                    "line=",
                    r.get("line"),
                    "|",
                    "evidence=",
                    r.get("evidence") or r.get("snippet", "")
                )
        else:
            print("NO ORIGINAL MATCH ON THIS LINE")
