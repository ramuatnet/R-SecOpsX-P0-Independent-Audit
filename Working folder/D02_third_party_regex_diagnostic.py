import importlib.util
from pathlib import Path

ROOT = Path(r"D:\data\Code test\R-SecOpsX_V11")
ENGINE = ROOT / "analysis" / "privacy_data_exposure_engine.py"

spec = importlib.util.spec_from_file_location("d02_pattern_diag", ENGINE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

text = "requests.post('https://example.invalid', json={'email': user.email})"

print("=" * 72)
print("D-02 THIRD-PARTY REGEX PIPELINE DIAGNOSTIC")
print("=" * 72)

print("\n[INPUT]")
print(text)

print("\n[1] LITERAL PREFILTER")
low = text.lower()

for name, literals in m._PRIVACY_EXPOSURE_LITERAL_FAMILIES:
    if name == "PII_THIRD_PARTY_TRANSFER":
        print("family:", name)
        print("literals:", literals)
        print("matches:", [x for x in literals if x in low])
        print(
            "candidate:",
            m._privacy_exposure_candidate(
                "PII_THIRD_PARTY_TRANSFER",
                low
            )
        )

print("\n[2] COMPILED PATTERN")
for indicator, pattern, risk, impact in m._V17925_COMPILED_EXPOSURE_PATTERNS:
    if indicator == "PII_THIRD_PARTY_TRANSFER":
        print("indicator:", indicator)
        print("risk:", risk)
        print("pattern:", pattern.pattern)
        print("regex_match:", bool(pattern.search(text)))
        if pattern.search(text):
            print("MATCH:", pattern.search(text).group(0))

print("\n[3] FAST HELPER")
print(m._privacy_exposure_hits_fast(text))

print("\n[4] BOUNDED HELPER")
print(m._privacy_exposure_hits_bounded(text))

print("\n[5] EXPOSURE PATTERNS DIRECT")
for indicator, pattern, risk, impact in m.EXPOSURE_PATTERNS:
    if indicator == "PII_THIRD_PARTY_TRANSFER":
        print("raw pattern:", pattern)
        print("raw match:", bool(pattern and __import__("re").search(pattern, text, __import__("re").I)))

print("=" * 72)
