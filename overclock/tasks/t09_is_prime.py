SPEC = """
slow(nums) returns a list of bools: for each n in `nums`, True if n is a prime number, else False.
Numbers < 2 are not prime. `nums` is a list of non-negative ints. Return a list of bools.
"""
TAGS = ["primes", "sqrt-bound"]


def slow(nums):
    out = []
    for n in nums:
        if n < 2:
            out.append(False)
            continue
        prime = True
        for d in range(2, n):
            if n % d == 0:
                prime = False
                break
        out.append(prime)
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(([r.randint(0, 40_000) for _ in range(400)],))
    return out
