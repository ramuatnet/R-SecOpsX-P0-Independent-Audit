import importlib.util
import inspect
from pathlib import Path

ROOT = Path(r"D:\data\Code test\R-SecOpsX_V11")
ENGINE = ROOT / "analysis" / "privacy_data_exposure_engine.py"

spec = importlib.util.spec_from_file_location("d02_active_engine", ENGINE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

text = "requests.post('https://example.invalid', json={'email': user.email})"

print("=" * 80)
print("D-02 ACTIVE FAST-PATH SOURCE DIAGNOSTIC")
print("=" * 80)

print("\n[1] ACTIVE FUNCTION SOURCE")
print(inspect.getsource(m._privacy_exposure_hits_fast))

print("\n[2] ACTIVE CANDIDATE FUNCTION SOURCE")
print(inspect.getsource(m._privacy_exposure_candidate))

print("\n[3] MANUAL FAST-LOOP REPLAY")

low = m._privacy_candidate_lower(text)

print("low:", low)

for indicator, pattern, risk, impact in m._V17925_COMPILED_EXPOSURE_PATTERNS:

    if indicator != "PII_THIRD_PARTY_TRANSFER":
        continue

    candidate = m._privacy_exposure_candidate(indicator, low)
    regex_match = bool(pattern.search(text))

    print("indicator       :", repr(indicator))
    print("candidate       :", candidate)
    print("regex_match     :", regex_match)
    print("risk            :", repr(risk))
    print("impact          :", repr(impact))

    if candidate and regex_match:
        print("MANUAL RESULT   : HIT")
    else:
        print("MANUAL RESULT   : NO HIT")

print("\n[4] ACTUAL HELPERS")

print("FAST    :", m._privacy_exposure_hits_fast(text))
print("BOUNDED :", m._privacy_exposure_hits_bounded(text))

print("\n[5] FUNCTION CODE LOCATIONS")

print(
    "_privacy_exposure_hits_fast:",
    inspect.getsourcefile(m._privacy_exposure_hits_fast),
    inspect.getsourcelines(m._privacy_exposure_hits_fast)[1],
)

print(
    "_privacy_exposure_candidate:",
    inspect.getsourcefile(m._privacy_exposure_candidate),
    inspect.getsourcelines(m._privacy_exposure_candidate)[1],
)

print(
    "_privacy_exposure_hits_bounded:",
    inspect.getsourcefile(m._privacy_exposure_hits_bounded),
    inspect.getsourcelines(m._privacy_exposure_hits_bounded)[1],
)

print("\n[6] ALL DEFINITIONS IN SOURCE")

source = ENGINE.read_text(encoding="utf-8")

for name in (
    "def _privacy_exposure_candidate",
    "def _privacy_exposure_hits_fast",
    "def _privacy_exposure_hits_bounded",
):
    positions = []
    start = 0
    while True:
        pos = source.find(name, start)
        if pos < 0:
            break
        positions.append(source[:pos].count("\n") + 1)
        start = pos + 1

    print(name, "=>", positions)

print("=" * 80)
