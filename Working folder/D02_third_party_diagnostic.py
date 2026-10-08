import importlib.util

path = r".\analysis\privacy_data_exposure_engine.py"

spec = importlib.util.spec_from_file_location("privacy_engine", path)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

text = "requests.post('https://example.invalid', json={'email': user.email})"

print("=" * 72)
print("D-02 THIRD-PARTY TRANSFER CLASSIFIER DIAGNOSTIC")
print("=" * 72)

print("\n[INPUT]")
print(text)

print("\n[EXPOSURE PATTERN MATCHES]")
hits = []
for indicator, pattern, risk, impact in engine.EXPOSURE_PATTERNS:
    import re
    if re.search(pattern, text, re.IGNORECASE):
        hits.append((indicator, risk, impact))
        print("MATCH:", indicator, "|", risk)

print("\n[PII VALUE]")
print(engine._has_pii_value(text))

print("\n[REQUEST SIDE ONLY]")
print(engine._is_request_side_only(text))

print("\n[RESPONSE SINK]")
print(engine._has_response_sink(text))

print("\n[CHALLENGE CONTEXT]")
print(engine._is_challenge_context(text))

print("\n[CLASSIFIER]")
print(engine._classify_exposure(text, hits))

print("\n[FINAL HITS]")
print(hits)

print("=" * 72)
