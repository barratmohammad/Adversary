SPEC = """
slow(data, ks) returns, for each k in `ks`, the k-th smallest element of `data` (0-indexed), as a list.
`data` is a non-empty list of ints; every k satisfies 0 <= k < len(data). Return a list of ints.
"""
TAGS = ["repeated-sort", "hoisting"]


def slow(data, ks):
    out = []
    for k in ks:
        out.append(sorted(data)[k])
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        data = [r.randint(-10_000, 10_000) for _ in range(3000)]
        ks = [r.randrange(len(data)) for _ in range(300)]
        out.append((data, ks))
    return out
