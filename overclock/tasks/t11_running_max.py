SPEC = """
slow(nums) returns the running maximum: a list where element i is max(nums[0..i]).
`nums` is a list of ints (possibly empty). Return a list of ints.
"""
TAGS = ["prefix", "quadratic"]


def slow(nums):
    out = []
    for i in range(len(nums)):
        out.append(max(nums[: i + 1]))
    return out


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(([r.randint(-1_000_000, 1_000_000) for _ in range(5000)],))
    return out
