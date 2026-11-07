SPEC = """
slow(limit) returns how many prime numbers p satisfy 2 <= p <= limit. `limit` is a non-negative int.
Return an int.
"""
TAGS = ["primes", "sieve", "sqrt-bound"]


def slow(limit):
    count = 0
    for n in range(2, limit + 1):
        prime = True
        for d in range(2, n):
            if n % d == 0:
                prime = False
                break
        if prime:
            count += 1
    return count


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    return [(r.randint(9000, 14_000),) for _ in range(n)]
