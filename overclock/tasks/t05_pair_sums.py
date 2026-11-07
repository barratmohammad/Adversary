SPEC = """
slow(nums, target) returns the number of index pairs (i, j) with i < j and nums[i] + nums[j] == target.
`nums` is a list of ints, `target` is an int. Return an int.
"""
TAGS = ["quadratic", "counter"]


def slow(nums, target):
    count = 0
    n = len(nums)
    for i in range(n):
        for j in range(i + 1, n):
            if nums[i] + nums[j] == target:
                count += 1
    return count


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        nums = [r.randint(0, 200) for _ in range(1200)]
        out.append((nums, r.randint(50, 300)))
    return out
