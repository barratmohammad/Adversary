SPEC = """
slow(names, lookups) returns, for each name in `lookups`, the index of its first occurrence in `names`,
or -1 if absent. `names` and `lookups` are lists of str. Return a list of ints.
"""
TAGS = ["index-lookup", "dict"]


def slow(names, lookups):
    out = []
    for name in lookups:
        found = -1
        for i in range(len(names)):
            if names[i] == name:
                found = i
                break
        out.append(found)
    return out


def gen_inputs(seed, n):
    import random
    import string

    r = random.Random(seed)
    out = []
    for _ in range(n):
        vocab = ["".join(r.choices(string.ascii_lowercase, k=5)) for _ in range(4000)]
        names = [r.choice(vocab) for _ in range(3000)]
        lookups = [r.choice(vocab) for _ in range(1200)]
        out.append((names, lookups))
    return out
