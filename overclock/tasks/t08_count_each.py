SPEC = """
slow(items) returns a list of [value, count] pairs for every distinct value in `items`,
sorted by value ascending. `items` is a list of ints. Return a list of 2-element lists.
"""
TAGS = ["counting", "counter"]


def slow(items):
    out = []
    for v in sorted(set(items)):
        out.append([v, items.count(v)])
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(([r.randint(0, 600) for _ in range(4000)],))
    return out
