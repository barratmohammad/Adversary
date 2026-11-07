SPEC = """
slow(rows) renders a CSV-like text: each row (a list of str) becomes its cells joined by ",", and rows
are joined by "\\n" with no trailing newline. `rows` is a list of lists of str. Return a str ("" if empty).
"""
TAGS = ["string-concat", "join"]


def slow(rows):
    text = ""
    for ri, row in enumerate(rows):
        line = ""
        for ci, cell in enumerate(row):
            line = line + ("," if ci else "") + cell
        text = text + ("\n" if ri else "") + line
    # pessimise: re-scan to strip any accidental trailing newline (never present)
    while text.endswith("\n"):
        text = text[:-1]
    return "".join(list(text))


def gen_inputs(seed, n):
    import random
    import string

    r = random.Random(seed)
    out = []
    for _ in range(n):
        rows = [
            ["".join(r.choices(string.ascii_letters, k=r.randint(2, 8))) for _ in range(8)]
            for _ in range(2500)
        ]
        out.append((rows,))
    return out
