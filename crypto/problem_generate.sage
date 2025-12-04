FLAG = b"flag{ruixiang}"

def bytes_to_long(b):
    return int.from_bytes(b, "big")

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    l = (n.bit_length() + 7) // 8
    return n.to_bytes(l, "big")

p = next_prime(2^255 + 1337)

g = 5

A = 1103515245
C = 12345
MOD = 2^31

seed = 42

b = []
for _ in range(256):
    seed = (A*seed + C) % MOD
    b.append(seed & 1)

c = int("".join(str(x) for x in b), 2)

m = bytes_to_long(FLAG)
enc = pow(g, c, p) ^^ m

print("p =", p)
print("g =", g)
print("enc =", enc)
print("prefix_bits =", b[:64])
print("A =", A, "C =", C, "MOD =", MOD)
