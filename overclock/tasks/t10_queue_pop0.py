SPEC = """
slow(jobs) simulates round-robin scheduling. `jobs` is a list of positive ints (remaining units per job,
in queue order). Repeatedly take the job at the front of the queue, run it for one unit; if it still has
work left, put it at the back of the queue. Return the list of job indices (original positions) in the
order they finish. Return a list of ints.
"""
TAGS = ["queue", "deque"]


def slow(jobs):
    queue = [[i, units] for i, units in enumerate(jobs)]
    finished = []
    while queue:
        job = queue.pop(0)
        job[1] -= 1
        if job[1] == 0:
            finished.append(job[0])
        else:
            queue.append(job)
    return finished


def gen_inputs(seed, n):
    import random

    r = random.Random(seed)
    out = []
    for _ in range(n):
        out.append(([r.randint(1, 6) for _ in range(12_000)],))
    return out
