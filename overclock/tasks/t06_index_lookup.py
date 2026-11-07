SPEC = """
slow(data, queries) returns, for each q in `queries`, the index of the first occurrence of q in `data`,
or -1 if q is not present. `data` and `queries` are lists of ints. Return a list of ints.
"""
TAGS = ["index-lookup", "dict"]


def slow(data, queries):
    out = []
    for q in queries:
        if q in data:
            out.append(data.index(q))
        else:
            out.append(-1)
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        data = [r.randint(0, 20_000) for _ in range(3000)]
        queries = [r.randint(0, 25_000) for _ in range(1500)]
        out.append((data, queries))
    return out
