SPEC = """
slow(items) returns the list of distinct items in first-seen order (order-preserving de-duplication).
`items` is a list of ints. Return a list of ints.
"""
TAGS = ["dedupe", "set", "membership"]


def slow(items):
    result = []
    for x in items:
        if x not in result:
            result.append(x)
    return result


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(([r.randint(0, 3000) for _ in range(5000)],))
    return out
