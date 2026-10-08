import pstats

p = pstats.Stats(r".\analysis\main_pipeline.prof")

print("=" * 100)
print("R-SecOpsX CPROFILE - TOP FUNCTIONS BY CUMULATIVE TIME")
print("=" * 100)

p.sort_stats("cumulative").print_stats(40)

print("\n")
print("=" * 100)
print("R-SecOpsX CPROFILE - TOP FUNCTIONS BY INTERNAL TIME")
print("=" * 100)

p.sort_stats("tottime").print_stats(40)
