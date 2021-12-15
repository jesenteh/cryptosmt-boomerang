"""
@author: jesenteh
Date: 9 December, 2021
This Python script implements WARP and checks its correctness by using the test vectors provided in WARP's design specification.
It also computationally verifies the differential probability of a related-key differential found for WARP.
"""

from scipy.stats import norm
import math, random

rc0 = [0, 0, 1, 3, 7, 0xf, 0xf, 0xf, 0xe, 0xd, 0xa, 5, 0xa, 5, 0xb, 6, 0xc, 9, 3, 6, 0xd, 0xb, 7, 0xe, 0xd, 0xb, 6, 0xd, 0xa, 4, 9, 2, 4, 9, 3, 7, 0xe, 0xc, 8, 1, 2]
rc1 = [4, 0xc, 0xc, 0xc, 0xc, 0xc, 8, 4, 8, 4, 8, 4, 0xc, 8, 0, 4, 0xc, 8, 4, 0xc, 0xc, 8, 4, 0xc, 8, 4, 8, 0, 4, 8, 0, 4, 0xc, 0xc, 8, 0, 0, 4, 8, 4, 0xc]
s = [0xc, 0xa, 0xd, 3, 0xe, 0xb, 0xf, 7, 8, 9, 1, 5, 0, 2, 4, 6]
perm = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2, 3, 0, 25, 4, 23, 10, 15, 22, 13, 30, 17, 28, 5, 24, 11, 18, 19, 16, 9, 20, 7, 26]


def printHex(x):
    print("0x",end="")
    for i in x:
        print("{:x}".format(i), end="")
    print("")

def roundFunc(p, k, r, rounds):
    #Feistel
    temp = []

    #Nibbles 0 and 1
    temp.append(p[0])
    val = s[p[0]] ^ p[1] ^ k[0] ^ rc0[r]
    temp.append(val)

    #Nibbles 2 and 3
    temp.append(p[2])
    val = s[p[2]] ^ p[3] ^ k[1] ^ rc1[r]
    temp.append(val)

    #The rest of the nibbles
    for i in range (4, 32, 2):
        temp.append(p[i])
        val = s[p[i]] ^ p[i+1] ^ k[int(i/2)]
        temp.append(val)

    #Permutation
    #Do not permute if final round
    if r != (rounds-1):
        for i in range (0, 32):
            p[perm[i]] = temp[i]
    else:
        p = temp

    return p

def enc(p1, p0, k1, k0, rounds):
    
    mask = 0xF
    p = []
    for i in range (0, 16):
        p.append(p0 & mask)
        p0=p0>>4


    for i in range (0, 16):
        p.append(p1 & mask)
        p1=p1>>4


    K0 = []
    for i in range (0, 16):
        K0.append(k0 & mask)
        k0=k0>>4


    K1 = []
    for i in range (0, 16):
        K1.append(k1 & mask)
        k1=k1>>4

    for r in range (0, rounds):
        if r % 2 == 0:
            p = roundFunc(p, K0, r, rounds)
        else:
            p = roundFunc(p, K1, r, rounds)
    return p

def checkDiff(diff,rounds):

    #Target difference
    if (rounds%2!=0):
        p0 = 0x0000010000000000
        p1 = 0x0000000000000000
    else:
        p0 = 0x0000000000001000
        p1 = 0x0000000000000000


    mask = 0xF
    p = []
    for i in range (0, 16):
        p.append(p0 & mask)
        p0=p0>>4

    for i in range (0, 16):
        p.append(p1 & mask)
        p1=p1>>4

    return p==diff

def verifyRK(pairs, rounds):

    # #Key
    k0_1 = random.getrandbits(64)
    k1_1 = random.getrandbits(64)
    #Related key
    k0_2 = k0_1 ^ 0x0000000010000010
    k1_2 = k1_1 ^ 0x0000000000200000


    m1 = []
    m2 = []

    numpairs = int(math.pow(2,pairs))
    countpairs = 0
    for i in range (0, numpairs):
        #Randomly generate the first plaintext
        p0_1 = random.getrandbits(64)
        p1_1 = random.getrandbits(64)

        #Generate the second plaintext with the required difference
        p0_2 = p0_1 ^ 0x0000000000001000
        p1_2 = p1_1 ^ 0x0000000000000000

        m1 = enc(p1_1, p0_1, k1_1, k0_1, rounds)
        m2 = enc(p1_2, p0_2, k1_2, k0_2, rounds)
          

        temp = []
        diff = []
        for i in range (0,32):
            temp.append(m1[i]^m2[i])
            diff.append(0)  
        
        #Permute
        for i in range (0, 32):
            diff[perm[i]]=temp[i]

        #Check difference and increment counter
        countpairs = countpairs + checkDiff(diff,rounds)
    print("Number of input pairs = 2^{}".format(pairs))
    print("Valid pairs = 2^{}".format(math.log(countpairs,2)))
    print("Differential probability = 2^{}".format(math.log(countpairs,2)-pairs))
    return math.log(countpairs,2)-pairs


def main():
    """
    Note:
    The way the original represents the data is the inverse of what is done in cryptanalysis paper.
    Original WARP paper 0 to 31 from left to right.
    Cryptanalysis paper 31 to 0 from left to right. 
    When setting up the following test vectors, 0 is the rightmost nibble (following the cryptanalysis paper and regular binary data convention).
    The printHex function will iterate and print each element in the list from 0 to 31 (following the original WARP paper).
    """

    # #Test Vector 1 (Remember it is flipped)
    k0 = 0xFEDCBA9876543210
    k1 = 0x0123456789ABCDEF
    p0 = 0xFEDCBA9876543210
    p1 = 0x0123456789ABCDEF
    rounds = 41
    p = enc(p1, p0, k1, k0, rounds)
    printHex(p)
    #Test Vector 2
    k1 = 0x0123456789ABCDEF
    k0 = 0xFEDCBA9876543210
    p1 = 0xFFEEDDCCBBAA9988
    p0 = 0x7766554433221100
    p = enc(p1, p0, k1, k0, rounds)
    printHex(p)
    #Test Vector 3
    k1 = 0x7D3E90B7680C30EE
    k0 = 0xF745A086F220DCA0
    p1 = 0x1E193D8021DCB798
    p0 = 0xAAE6A5CF09DDC6FA
    p = enc(p1, p0, k1, k0, rounds)
    printHex(p)

    #Verify
    rounds = 9 
    print("\nVerification for {}-round related-key trail with expected probability of 2^({})".format(rounds,rounds-1))
    #In log2
    numpairs = 11
    ave = 0
    numtest = 100
    for i in range (0, numtest):
        ave = ave + verifyRK(numpairs, rounds)
    ave = ave/numtest
    print(ave)


if __name__ == '__main__':
    main()
