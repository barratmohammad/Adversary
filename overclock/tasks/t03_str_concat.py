SPEC = """
slow(words) returns a single string: the words joined by ", " in order, with no trailing separator.
`words` is a list of str (possibly empty, in which case return ""). Return a str.
"""
TAGS = ["string-concat", "join"]


def slow(words):
    result = ""
    for i in range(len(words)):
        if i == 0:
            result = ", ".join([result, words[i]])[2:]
        else:
            result = ", ".join([result, words[i]])
    return result


def gen_inputs(seed, n):
    import random
    import string

    r = random.Random(seed)
    out = []
    for _ in range(n):
        words = ["".join(r.choices(string.ascii_lowercase, k=r.randint(3, 9))) for _ in range(16000)]
        out.append((words,))
    return out
