SPEC = """
slow(n) returns the n-th Tribonacci number: T(0)=0, T(1)=0, T(2)=1, T(k)=T(k-1)+T(k-2)+T(k-3).
n is a non-negative int (0 <= n <= 60 in practice). Return an int.
"""
TAGS = ["recursion", "memoization"]


def slow(n):
    def t(k):
        if k == 0 or k == 1:
            return 0
        if k == 2:
            return 1
        return t(k - 1) + t(k - 2) + t(k - 3)

    return t(n)


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    return [(r.randint(19, 22),) for _ in range(n)]
