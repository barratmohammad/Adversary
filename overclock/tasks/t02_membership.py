SPEC = """
slow(pool, queries) returns how many items of `queries` (counting repeats) are present in `pool`.
Both are lists of ints. Return an int.
"""
TAGS = ["membership", "set"]


def slow(pool, queries):
    hits = 0
    for q in queries:
        if q in pool:
            hits += 1
    return hits


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        pool = [r.randint(0, 50_000) for _ in range(3000)]
        queries = [r.randint(0, 60_000) for _ in range(1500)]
        out.append((pool, queries))
    return out
