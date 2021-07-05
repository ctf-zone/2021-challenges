from sage.all import *
from params import A, B, g, p

g = Integer(2)
p = Integer(p)
A = Integer(A)
B = Integer(B)
k = 10
n = p.nbits()


def build_basis(p, bit_bias, collected):
    matrix = []
    medium = pow(2, p.nbits() - bit_bias - 2)
    for i in range(len(collected)):
        t = [QQ(0)] * (len(collected) + 2)
        t[i] = QQ(p)
        matrix.append(t)
    qq_collected = list(map(QQ, collected))
    qq_collected.append(QQ(pow(2, bit_bias)) / (QQ(p)))
    qq_collected.append(QQ(0))
    average = []
    for i in range(len(collected)):
        average.append(QQ(medium))
    average.append(QQ(0))
    average.append(QQ(medium))
    matrix.append(qq_collected)
    matrix.append(average)
    return Matrix(matrix).LLL()


with open("values.txt", "r") as f:
    lines = f.read().strip().split("\n")

values = list(map(lambda x: int(x), lines))

basis_matrix = build_basis(p, k, values)

medium = pow(2, p.nbits() - k - 2)
possible = []
for i in range(len(values) + 2):
    x = basis_matrix[i][-1]
    if x == medium:
        v = (basis_matrix[i][-2] * p) // pow(2, k)

        if v < 0:
            v = -v

        possible.append(v)
        possible.append(p - v)

with open("possible.txt", "w") as f:
    for v in possible:
        f.write(str(v) + "\n")
