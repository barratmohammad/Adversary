SPEC = """
slow(a, b) returns the list of elements of `a` (in order, with repeats) that also appear anywhere in `b`.
`a` and `b` are lists of ints. Return a list of ints.
"""
TAGS = ["membership", "set"]


def slow(a, b):
    out = []
    for x in a:
        if x in b:
            out.append(x)
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        a = [r.randint(0, 40_000) for _ in range(2000)]
        b = [r.randint(0, 40_000) for _ in range(3000)]
        out.append((a, b))
    return out
