SPEC = """
slow(lists) returns a single flat list containing all elements of the sub-lists in order.
`lists` is a list of lists of ints. Return a list of ints.
"""
TAGS = ["flatten", "quadratic-concat"]


def slow(lists):
    result = []
    for sub in lists:
        result = result + sub
    return result


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        lists = [[r.randint(0, 99) for _ in range(r.randint(0, 12))] for _ in range(4000)]
        out.append((lists,))
    return out
