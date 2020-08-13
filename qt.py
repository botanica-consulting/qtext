import pickle

weird_bitfield = [0xff, 0xff, 0xff, 0xff, 1] + [0] * 26 + [80]

def check_bitmap(a):
    upper = a >> 3
    lower = a & (2 **3)
    return (weird_bitfield[upper] >> lower) & 1

assert(check_bitmap(0x70) == 0)
assert(check_bitmap(0x10) == 1)
assert(check_bitmap(0x26) == 1)


def clobber(b): 
    for i in range(len(b)): 
        for j in range(len(b)): 
            b[i] = (b[i] + b[j]) & 0xff
        if check_bitmap(b[i]) == 1:
            q = hex(b[i])
            r=  check_bitmap(b[i])
            # print(f"check_bitmap({q}) = {r}")
            # import pdb; pdb.set_trace()
            b[i] += 0x22
            b[i] &= 0xff
    return b

def passencode(p):
    a = clobber(bytearray((p).encode('latin1')))
    # print(bytes(a).hex())

    a = a * 4
    a = clobber(a)
    return a

def pr(a):
    print(bytes(a).hex())

if __name__ == "__main__":
    import sys
    if sys.argv[1] == '-f': 
        l = {}
        for i in range(10000):
            l[i] = passencode('%.4d' % (i,))
        open('dict.txt', 'wb').write(pickle.dumps(l))
    else:
        pr(passencode(sys.argv[1]))
