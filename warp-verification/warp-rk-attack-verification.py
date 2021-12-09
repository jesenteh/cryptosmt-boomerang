"""
@author: jesenteh
Date: 9 December, 2021
This Python script implements the 25-round key-recovery attack against WARP in the related-key setting.
"""

from scipy.stats import norm
import math, random

#Constants, S-box, Permutation
rc0 = [0, 0, 1, 3, 7, 0xf, 0xf, 0xf, 0xe, 0xd, 0xa, 5, 0xa, 5, 0xb, 6, 0xc, 9, 3, 6, 0xd, 0xb, 7, 0xe, 0xd, 0xb, 6, 0xd, 0xa, 4, 9, 2, 4, 9, 3, 7, 0xe, 0xc, 8, 1, 2]
rc1 = [4, 0xc, 0xc, 0xc, 0xc, 0xc, 8, 4, 8, 4, 8, 4, 0xc, 8, 0, 4, 0xc, 8, 4, 0xc, 0xc, 8, 4, 0xc, 8, 4, 8, 0, 4, 8, 0, 4, 0xc, 0xc, 8, 0, 0, 4, 8, 4, 0xc]
s = [0xc, 0xa, 0xd, 3, 0xe, 0xb, 0xf, 7, 8, 9, 1, 5, 0, 2, 4, 6]
perm = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2, 3, 0, 25, 4, 23, 10, 15, 22, 13, 30, 17, 28, 5, 24, 11, 18, 19, 16, 9, 20, 7, 26]
inv_perm = [11, 4, 9, 10, 13, 22, 1, 30, 7, 28, 15, 24, 5, 18, 3, 16, 27, 20, 25, 26, 29, 6, 17, 14, 23, 12, 31, 8, 21, 2, 19, 0]


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

#Decrypt a pair of nibbles at a particular index for a specific round
def decryptNibble(x0, x1, key, round, index):
    #RC0
    if index == 0:
        val = x1 ^ s[x0] ^ key ^ rc0[round-1]
    #RC1
    elif index == 2:
        val = x1 ^ s[x0] ^ key ^ rc1[round-1]
    else:
        val = x1 ^ s[x0] ^ key

    return val



def main():
    """
    Note:
    The way the original represents the data is the inverse of what is done in cryptanalysis paper.
    Original WARP paper 0 to 31 from left to right.
    Cryptanalysis paper 31 to 0 from left to right. 
    The printHex function will iterate and print each element in the list from 0 to 31 (following the original WARP paper).
    """

    #Number of rounds for the attack
    rounds = 25
    #Number of pairs in log2
    pairs = 17
    
    #Key    
    K0_1 = 0xFEDCBA9876543210
    K1_1 = 0xFEDCBA9876543210

    #Related key
    K0_2 = K0_1 ^ 0x0000000010000010
    K1_2 = K1_1 ^ 0x0000000000200000


    numpairs = int(math.pow(2,pairs))
    filteredpairs = 0
    combinations0 = 0
    combinations1 = 0
    combinations2 = 0
    combinations3 = 0
    countedpairs0 = 0
    countedpairs1 = 0
    countedpairs2 = 0
    countedpairs3 = 0

    countmatches = 0
    keyCounter = {}
    highest = 0

    """
    In the following, each pair will be associated to the guessed keys, and discarded if it is not valid. 
    Each remaining pair will then vote for the candidate keys associated with it.
    """
    #Generate pairs
    m1 = []
    m2 = []
    for i in range (0, numpairs):
        #Randomly generate the first plaintext
        p0_1 = random.getrandbits(64)
        p1_1 = random.getrandbits(64)

        #Generate the second plaintext with the required difference
        p0_2 = p0_1 ^ 0x0000000000001000
        p1_2 = p1_1 ^ 0x0000000000000000

        m1 = enc(p1_1, p0_1, K1_1, K0_1, rounds)
        m2 = enc(p1_2, p0_2, K1_2, K0_2, rounds)
          
        #Check for surviving pairs (Step 1 Key Recovery)
        if ( (s[m1[26]]^s[m2[26]]) ^ (m1[27] ^ m2[27]) != 0):
            #If pair is invalid, discard
            continue
        filteredpairs = filteredpairs+1 

        #Guess key to perform decryption in the previous round
        #Calculate the difference
        #Check the filter to see if the key/pair is valid, discard if not

        #ROUND24
        #To decrypt x24_29 and check if it matches Y23_39, need to guess k0_4 (no key difference) to decrypt X25_9 to obtain Y24_9
        k0_4 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[8], m1[9], k, 25, 8)
            #Decrypt m2
            x0_2 = decryptNibble(m2[8], m2[9], k, 25, 8)

            x1_1 = m1[20]
            x1_2 = m2[20]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) ^ 0 == 0):
                #If pair is valid, store key, we still expect the same number of pairs (2^14) - Correct
                k0_4.append(k)
                combinations0 = combinations0 + 1
                check = check + 1
        if check == 0: 
            #If no key+pair fulfils difference, discard
            continue
        countedpairs0 = countedpairs0 + 1
        
        #To decrypt x24_21 and check if it matches Y23_21, need to guess k0_8 (no key difference) to decrypt X25_17 to obtain Y24_17
        k0_8 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[16], m1[17], k, 25, 16)
            #Decrypt m2
            x0_2 = decryptNibble(m2[16], m2[17], k, 25, 16)

            x1_1 = m1[28]
            x1_2 = m2[28]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key, we still expect the same number of pairs (2^14) - 
                k0_8.append(k)
                combinations1 = combinations1 + len(k0_4)
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue
        countedpairs1 = countedpairs1 + 1

        #To decrypt x24_1 and check if it matches Y23_1, need to guess k0_15 (no key difference) to decrypt X25_31 to obtain Y24_31
        k0_15 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[30], m1[31], k, 25, 30)
            #Decrypt m2
            x0_2 = decryptNibble(m2[30], m2[31], k, 25, 30)

            x1_1 = m1[6]
            x1_2 = m2[6]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key, we still expect the same number of pairs (2^14) - 
                k0_15.append(k)
                combinations2 = combinations2 + len(k0_4)*len(k0_8)
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue
        countedpairs2 = countedpairs2 + 1

        # #ROUND23
        # #Calculate X23_31 = X24_26 = Y24_19, we guess k0_9 (no key difference) to decrypt X25_19
        # #To calculate X23_30 = Y23_7, we need to first guess k0_10 to decrypt X25_21, then guess k1_3 to decrypt X24_7
        # #TODO: Nested for loops for all 3 keys, valid combinations are included into a list containing [k0_9, k0_10, k1_3]. 
        # #At this point, there are 2^14 remaining combinations of pairs associated with 24 guessed key bits. Can already do counting.
        K23 = []
        check = 0
        #k0_9
        for k1 in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x23_31_1 = decryptNibble(m1[18], m1[19], k1, 25, 18)
            #Decrypt m2
            x23_31_2 = decryptNibble(m2[18], m2[19], k1, 25, 18)

            #k0_10
            for k2 in range (0, int(math.pow(2,4))):
                #Decrypt m1
                x24_6_1 = decryptNibble(m1[20], m1[21], k2, 25, 20)
                #Decrypt m2
                x24_6_2 = decryptNibble(m2[20], m2[21], k2, 25, 20)

                x24_7_1 = m1[8]
                x24_7_2 = m2[8]

                #k1_3
                for k3 in range (0, int(math.pow(2,4))):
                    #Decrypt X24
                    x23_30_1 = decryptNibble(x24_6_1, x24_7_1, k3, 24, 6)
                    #Decrypt X24
                    x23_30_2 = decryptNibble(x24_6_2, x24_7_2, k3, 24, 6)

                    tempkey = []
                    #Check for surviving pairs
                    if ( (s[x23_30_1] ^ s[x23_30_2]) ^ (x23_31_1 ^ x23_31_2) == 0):
                        #If pair is valid, store key, we still expect the same number of pairs (2^14) - 
                        tempkey.append(k1)
                        tempkey.append(k2)
                        tempkey.append(k3)
                        K23.append(tempkey)
                        combinations3 = combinations3 + len(k0_4)*len(k0_8)*len(k0_15)
                        check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue
        countedpairs3 = countedpairs3 + 1

        #Count the keys for each pair
        #Create index
        for k0 in k0_4:
            for k1 in k0_8:   
                for k2 in k0_15:
                    for keylist in K23:
                        if k0==4 and k1==8 and k2==15 and keylist[0]==9 and keylist[1]==10 and keylist[2]==3 :
                            countmatches = countmatches+1
                        #Representation = k0_4||k0_8||k0_15||k0_9||k0_10||k1_3
                        temp = "{:x}{:x}{:x}{:x}{:x}{:x}".format(k0, k1, k2, keylist[0], keylist[1], keylist[2])
                        index = int(temp, base=16)
                        if index not in keyCounter:
                            keyCounter[index]=1
                            if highest < keyCounter[index]:
                                highest = keyCounter[index]
                        else:
                            keyCounter[index]=keyCounter[index]+1
                            if highest < keyCounter[index]:
                                highest = keyCounter[index]

    print("Number of input pairs = 2^{}".format(pairs))
    print("Step 1: Valid pairs after filtering Round 25 = 2^{}".format(math.log(filteredpairs,2)))
    print("")

    print("Valid pairs after first guess = 2^{}".format(math.log(countedpairs0,2)))
    print("Number of combinations after first guess = 2^{}".format(math.log(combinations0,2)))
    print("")

    print("Valid pairs after second guess = 2^{}".format(math.log(countedpairs1,2)))
    print("Number of combinations after second guess = 2^{}".format(math.log(combinations1,2)))
    print("")

    print("Valid pairs after third guess = 2^{}".format(math.log(countedpairs2,2)))
    print("Number of combinations after third guess = 2^{}".format(math.log(combinations2,2)))
    print("")

    print("Valid pairs after fourth guess = 2^{}".format(math.log(countedpairs3,2)))
    print("Number of combinations after fourth guess = 2^{}".format(math.log(combinations3,2)))
    print("")

    print("Counter for the right key = 2^{}".format(math.log(countmatches,2)))


    counter = 0
    for key in keyCounter:
        if keyCounter[key] == highest:
            print(hex(key))
            counter = counter+1

    #Representation = k0_4||k0_8||k0_15||k0_9||k0_10||k1_3
    #48F9A3
    print("Highest counter = {}, Number of keys with the counter = {}, Target key counter = {}".format(highest, counter, keyCounter[0x48f9a3]))
    



if __name__ == '__main__':
    main()