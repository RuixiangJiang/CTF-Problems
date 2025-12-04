p = Integer(
    57896044618658097711785492504343953926634992332820282019728792003956564821503
)
g = Integer(
    5
)
enc = Integer(
    24842577697241748054250881795895795654674041610101329196284720891641927530601
)

prefix_bits = [
    [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
]

A = 1103515245
C = 12345
MOD = 2^31


known_c = None

full_bits = None

known_seed = 42


def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    l = (n.bit_length() + 7) // 8
    return int(n).to_bytes(l, "big")

def gen_bits_from_seed(seed, length=256):
    b = []
    s = Integer(seed)
    for _ in range(length):
        s = (A*s + C) % MOD
        b.append(int(s & 1))
    return b

def bits_to_int(bits):
    return Integer("".join(str(x) for x in bits), 2)


if known_c is not None:
    c = Integer(known_c)
    print("[+] Using known_c =", c)

elif full_bits is not None:
    print("[+] Using full_bits provided")
    c = bits_to_int(full_bits)

elif known_seed is not None:
    print("[+] Using known_seed, regenerating full bit string")
    full_bits = gen_bits_from_seed(known_seed, length=256)
    c = bits_to_int(full_bits)

else:
    print("[!] No known_c, full_bits, or known_seed provided.")
    print("[!] Falling back to seed search (this can be very slow).")

    found_seed = None

    # You can restrict the range for testing or chunk it.
    # For a full search use: range(MOD)
    for seed in range(MOD):
        # quick check only first len(prefix_bits) bits
        b_pref = gen_bits_from_seed(seed, length=len(prefix_bits))
        if b_pref == prefix_bits:
            found_seed = seed
            print("[+] Found seed:", seed)
            break

    if found_seed is None:
        print("[-] No seed found; check parameters.")
        raise SystemExit

    full_bits = gen_bits_from_seed(found_seed, length=256)
    c = bits_to_int(full_bits)


qc = pow(g, c, p)
flag_int = enc ^^ qc
flag = long_to_bytes(flag_int)

print("[+] FLAG bytes:", flag)
try:
    print("[+] FLAG (utf-8):", flag.decode())
except Exception:
    pass
