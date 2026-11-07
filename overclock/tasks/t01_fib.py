SPEC = """
slow(n) returns the n-th Fibonacci number, with fib(0)=0, fib(1)=1, fib(k)=fib(k-1)+fib(k-2).
n is a non-negative int (0 <= n <= 60 in practice). Return an int.
"""
TAGS = ["recursion", "memoization"]


def slow(n):
    def f(k):
        if k < 2:
            return k
        return f(k - 1) + f(k - 2)

    return f(n)


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    return [(r.randint(22, 25),) for _ in range(n)]
