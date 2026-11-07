SPEC = """
slow(text) returns the distinct whitespace-separated words of `text` in first-seen order.
`text` is a str. Return a list of str.
"""
TAGS = ["dedupe", "set", "membership"]


def slow(text):
    seen = []
    for w in text.split():
        if w not in seen:
            seen.append(w)
    return seen


def gen_inputs(seed, n):
    import random
    import string

    r = random.Random(seed)
    out = []
    for _ in range(n):
        vocab = ["".join(r.choices(string.ascii_lowercase, k=r.randint(2, 7))) for _ in range(2500)]
        text = " ".join(r.choice(vocab) for _ in range(6000))
        out.append((text,))
    return out
