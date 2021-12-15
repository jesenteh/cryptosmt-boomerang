"""
@author: jesenteh
Date: 9 December, 2021
This Python script implements the (r+6)-round key-recovery attack against WARP in the related-key setting
Related-key trail (i=3, x=1, y=2) - See paper
Distinguisher length, r must be an odd number (r=3,5,7,..,35)
For fast verification, use 9+6=15 rounds (9-round distinguisher 2^-8) and 2^12 pairs
For 25-round verification, change rounds to 25 and set to 2^21 or 2^22 pairs
"""

from scipy.stats import norm
import math, random


#Number of rounds for the attack
rounds = 15
#Number of pairs in log2
pairs = 9

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

    
    #Key
    K0_1 = random.getrandbits(64)
    K1_1 = random.getrandbits(64)

    #Target keys
    #k0_4
    t4 = K0_1 & 0x00000000000F0000
    t4 = t4>>16
    #k0_7
    t7 = K0_1 & 0x00000000F0000000
    t7 = t7>>28
    #k0_10
    t10 = K0_1 & 0x00000F0000000000
    t10 = t10>>40
    #k0_14
    t14 = K0_1 & 0x0F00000000000000
    t14 = t14>>56

    #Related key
    K0_2 = K0_1 ^ 0x0000000010000010
    K1_2 = K1_1 ^ 0x0000000000200000


    numpairs = int(math.pow(2,pairs))

    #Variables to keep track of pairs after filtering and number of pairs+key combinations
    filteredpairs = 0
    combinations=[0,0,0,0]
    #Key counters and variable to keep track of the number of keys with the highest count in the key counter
    keyCounter0 = {}
    keyCounter1 = {}
    keyCounter2 = {}
    keyCounter3 = {}
    highest=[0,0,0,0]
    #Variables to store plaintexts after encryption
    m1 = []
    m2 = []

    """
    In the following, we encrypt each pair and perform the guess-and-determine procedure.
    We will not store the plaintext-ciphertext pairs.
    """
    
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
        filter = [2,3,4,5,6,7,10,11,12,13,18,19,24,25,28]
        invalid = 0
        for i in filter:
            if (m1[i] ^ m2[i]) != 0:
                #If pair is invalid, discard
                invalid = 1
                break
        if invalid == 1:
            continue


        #Filter based on subround filters
        filter = [0,16,22,26,30]
        invalid = 0
        for i in filter:
            if ( (s[m1[i]]^s[m2[i]]) ^ (m1[i+1] ^ m2[i+1]) != 0):
                #If pair is invalid, discard
                invalid = 1
                break
        if invalid == 1:
            continue

        #If pair survives, increment the number of filtered pairs
        filteredpairs = filteredpairs+1 

        """
        Guess and determine procedure begins here, which will be performed for the subround filters 
        of the penultimate round.
        Guess keys from the final round to calculate the nibble that goes through the S-box in the 
        subround filter.
        Calculate the other nibble involved in the subround filter directly from the ciphertext pair
        Check the filter to see if the key/pair is valid, discard if not.
        """

        # ROUND (rounds-1)
        # To decrypt x(rounds-1)_29 and check if it matches Y(rounds-2)_29, 
        # need to guess k0_4 (no key difference) to decrypt X(rounds)_9 to obtain Y(rounds)_9
        k0_4 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[8], m1[9], k, rounds, 8)
            #Decrypt m2
            x0_2 = decryptNibble(m2[8], m2[9], k, rounds, 8)

            x1_1 = m1[20]
            x1_2 = m2[20]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_4.append(k)
                combinations[0] = combinations[0] + 1
                check = check + 1
        if check == 0: 
            #If no key+pair fulfils difference, discard
            continue

        
        # To decrypt x(rounds-1)_17 and check if it matches Y(rounds-2)_17,
        # need to guess k0_7 (key difference = 1) to decrypt X(rounds)_15 to obtain Y(rounds)_15
        k0_7 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[14], m1[15], k, rounds, 14)
            #Decrypt m2
            x0_2 = decryptNibble(m2[14], m2[15], k^1, rounds, 14)

            x1_1 = m1[22]
            x1_2 = m2[22]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_7.append(k)
                combinations[1] = combinations[1] + 1
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        #To decrypt x(rounds-1)_7 and check if it matches Y(rounds-2)_7, guess k0_10 with no key difference
        k0_10 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[20], m1[21], k, rounds, 20)
            #Decrypt m2
            x0_2 = decryptNibble(m2[20], m2[21], k, rounds, 20)

            x1_1 = m1[8]
            x1_2 = m2[8]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_10.append(k)
                combinations[2] = combinations[2] + 1
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        #To decrypt x(rounds-1)_3 and check if it matches Y(rounds-2)_3, guess k0_14 with no key difference
        k0_14 = []
        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = decryptNibble(m1[28], m1[29], k, rounds, 28)
            #Decrypt m2
            x0_2 = decryptNibble(m2[28], m2[29], k, rounds, 28)

            x1_1 = m1[14]
            x1_2 = m2[14]

            #Check for surviving pairs
            if ( (s[x0_1] ^ s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_14.append(k)
                combinations[3] = combinations[3] + 1
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        # Count the keys for each pair
        # Create index
        key_index = [4,7,10,14]

        for index in k0_4:
            if index not in keyCounter0:
                keyCounter0[index]=1
                if highest[0] < keyCounter0[index]:
                    highest[0] = keyCounter0[index]
            else:
                keyCounter0[index]=keyCounter0[index]+1
                if highest[0] < keyCounter0[index]:
                    highest[0] = keyCounter0[index]   

        for index in k0_7:   
            if index not in keyCounter1:
                keyCounter1[index]=1
                if highest[1] < keyCounter1[index]:
                    highest[1] = keyCounter1[index]
            else:
                keyCounter1[index]=keyCounter1[index]+1
                if highest[1] < keyCounter1[index]:
                    highest[1] = keyCounter1[index]   
        
        for index in k0_10:
            if index not in keyCounter2:
                keyCounter2[index]=1
                if highest[2] < keyCounter2[index]:
                    highest[2] = keyCounter2[index]
            else:
                keyCounter2[index]=keyCounter2[index]+1
                if highest[2] < keyCounter2[index]:
                    highest[2] = keyCounter2[index]  
        
        for index in k0_14:
            if index not in keyCounter3:
                keyCounter3[index]=1
                if highest[3] < keyCounter3[index]:
                    highest[3] = keyCounter3[index]
            else:
                keyCounter3[index]=keyCounter3[index]+1
                if highest[3] < keyCounter3[index]:
                    highest[3] = keyCounter3[index]  
     


    print("Number of input pairs = 2^{}".format(pairs))
    if filteredpairs == 0:
        print("No pairs found.")
        quit()

    print("Step 1: Valid pairs after filtering Round {} = 2^{}".format(rounds, math.log(filteredpairs,2)))
    print("")

    for i in range (0,4):
        print("Number of combinations for key #{}= 2^{}".format(i,math.log(combinations[0],2)))


    counter = 0
    for key in keyCounter0:
        if keyCounter0[key] == highest[0]:
            counter = counter+1    
    print("Highest counter = {}, Number of keys with the counter = {}, Target key counter = {}".format(highest[0], counter, keyCounter0[t4]))
    print("Length of key counter = 2^{}".format(math.log(len(keyCounter0),2)))

    counter = 0
    for key in keyCounter1:
        if keyCounter1[key] == highest[1]:
            counter = counter+1    
    print("Highest counter = {}, Number of keys with the counter = {}, Target key counter = {}".format(highest[1], counter, keyCounter1[t7]))
    print("Length of key counter = 2^{}".format(math.log(len(keyCounter1),2)))

    counter = 0
    for key in keyCounter2:
        if keyCounter2[key] == highest[2]:
            counter = counter+1    
    print("Highest counter = {}, Number of keys with the counter = {}, Target key counter = {}".format(highest[2], counter, keyCounter2[t10]))
    print("Length of key counter = 2^{}".format(math.log(len(keyCounter2),2)))

    counter = 0
    for key in keyCounter3:
        if keyCounter3[key] == highest[3]:
            counter = counter+1    
    print("Highest counter = {}, Number of keys with the counter = {}, Target key counter = {}".format(highest[3], counter, keyCounter3[t14]))
    print("Length of key counter = 2^{}".format(math.log(len(keyCounter3),2)))


if __name__ == '__main__':
    main()
