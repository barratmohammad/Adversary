SPEC = """
slow(nums, ranges) returns, for each [l, r] in `ranges`, the sum of nums[l:r] (r exclusive).
`nums` is a list of ints; every range satisfies 0 <= l <= r <= len(nums). Return a list of ints.
"""
TAGS = ["prefix-sums", "quadratic"]


def slow(nums, ranges):
    out = []
    for l, r in ranges:
        total = 0
        for i in range(l, r):
            total += nums[i]
        out.append(total)
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        nums = [r.randint(-100, 100) for _ in range(5000)]
        ranges = []
        for _ in range(600):
            a, b = sorted((r.randrange(5001), r.randrange(5001)))
            ranges.append([a, b])
        out.append((nums, ranges))
    return out
