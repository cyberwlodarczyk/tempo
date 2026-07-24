import sys
import json


def readline():
    while True:
        try:
            return int(sys.stdin.readline().rstrip("\n"))
        except:
            pass


def microseconds(ns: int):
    return f"{ns / 1000:.2f}µs"


iterations = readline()
data = []

for level in range(1, 6, 2):
    min = sys.maxsize
    max = 0
    sum = 0
    for j in range(iterations):
        ns = readline()
        sum += ns
        if ns < min:
            min = ns
        if ns > max:
            max = ns
    avg = sum / iterations
    diff = max - min
    data.append(
        {
            "level": level,
            "avg": microseconds(avg),
            "min": microseconds(min),
            "max": microseconds(max),
            "diff": microseconds(diff),
        }
    )

result = {"iterations": iterations, "data": data}

with open("perf_gen_matrix.json", "w+") as f:
    f.write(json.dumps(result, indent="\t", ensure_ascii=False))
