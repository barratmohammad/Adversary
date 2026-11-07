SPEC = """
slow(words) groups words that are anagrams of each other. Returns a list of groups; each group is the
list of words (in first-seen order) that are anagrams of one another; groups are ordered by the first
appearance of their first word. `words` is a list of lowercase str. Return a list of lists of str.
"""
TAGS = ["grouping", "dict-key"]


def slow(words):
    groups = []
    for w in words:
        placed = False
        for g in groups:
            if sorted(g[0]) == sorted(w):
                g.append(w)
                placed = True
                break
        if not placed:
            groups.append([w])
    return groups


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        bases = ["".join(r.choices("abcdefgh", k=r.randint(3, 6))) for _ in range(700)]
        words = []
        for _ in range(2500):
            b = list(r.choice(bases))
            r.shuffle(b)
            words.append("".join(b))
        out.append((words,))
    return out
