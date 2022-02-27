'''
Created on Nov 3, 2021

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class LBlockSCipher(AbstractCipher):
    """
    Represents the differential behaviour of LBlock-s and can be used
    to find differential characteristics for the given parameters.
    """

    name = "lblocks"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'S', 'F', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for LBlockS with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% LBlock-s w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = input (64), s = S-Box output (32), f = output of F function (32), r = rotation output (32)
            #p = swap 32-bit blocks (64)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            f = ["F{}".format(i) for i in range(rounds)]
            s = ["S{}".format(i) for i in range(rounds)]
            p = ["p{}".format(i) for i in range(rounds)]
            r = ["r{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, r, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupLBlockSRound(stp_file, x[i], s[i], p[i], f[i], r[i], x[i+1], 
                                     w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupLBlockSRound(self, stp_file, x_in, s, p, f, r, x_out, w, wordsize):
        """
        Model for differential behaviour of one round LBlock-s
        """
        command = ""

        # Substitution Layer
        lblock_sbox = [0xE, 9, 0xF, 0, 0xD, 4, 0xA, 0xB, 1, 2, 8, 3, 7, 6, 0xC, 5]
        for i in range(8):
            variables = ["{0}[{1}:{1}]".format(x_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(s, 4*i + 3),
                         "{0}[{1}:{1}]".format(s, 4*i + 2),
                         "{0}[{1}:{1}]".format(s, 4*i + 1),
                         "{0}[{1}:{1}]".format(s, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(lblock_sbox, variables)

        # Permutation Layer
        command += "ASSERT({0}[7:4] = {1}[3:0]);\n".format(s, f)
        command += "ASSERT({0}[15:12] = {1}[7:4]);\n".format(s, f)
        command += "ASSERT({0}[3:0] = {1}[11:8]);\n".format(s, f)
        command += "ASSERT({0}[11:8] = {1}[15:12]);\n".format(s, f)

        command += "ASSERT({0}[23:20] = {1}[19:16]);\n".format(s, f)
        command += "ASSERT({0}[31:28] = {1}[23:20]);\n".format(s, f)
        command += "ASSERT({0}[19:16] = {1}[27:24]);\n".format(s, f)
        command += "ASSERT({0}[27:24] = {1}[31:28]);\n".format(s, f)

        #Rotate left x[63:32] and store in 32-bit r
        command += "ASSERT({0}[63:56] = {1}[7:0]);\n".format(x_in, r)
        command += "ASSERT({0}[55:32] = {1}[31:8]);\n".format(x_in, r)

        #Feistel structure
        command += "ASSERT({0}[3:0] = {1}[3:0]);\n".format(x_in, p)
        command += "ASSERT({0}[7:4] = {1}[7:4]);\n".format(x_in, p)
        command += "ASSERT({0}[11:8] = {1}[11:8]);\n".format(x_in, p)
        command += "ASSERT({0}[15:12] = {1}[15:12]);\n".format(x_in, p)
        command += "ASSERT({0}[19:16] = {1}[19:16]);\n".format(x_in, p)
        command += "ASSERT({0}[23:20] = {1}[23:20]);\n".format(x_in, p)
        command += "ASSERT({0}[27:24] = {1}[27:24]);\n".format(x_in, p)
        command += "ASSERT({0}[31:28] = {1}[31:28]);\n".format(x_in, p)

        command += "ASSERT({0}[35:32] = BVXOR({1}[3:0],{2}[3:0]));\n".format(p, r, f)
        command += "ASSERT({0}[39:36] = BVXOR({1}[7:4],{2}[7:4]));\n".format(p, r, f)
        command += "ASSERT({0}[43:40] = BVXOR({1}[11:8],{2}[11:8]));\n".format(p, r, f)
        command += "ASSERT({0}[47:44] = BVXOR({1}[15:12],{2}[15:12]));\n".format(p, r, f)
        command += "ASSERT({0}[51:48] = BVXOR({1}[19:16],{2}[19:16]));\n".format(p, r, f)
        command += "ASSERT({0}[55:52] = BVXOR({1}[23:20],{2}[23:20]));\n".format(p, r, f)
        command += "ASSERT({0}[59:56] = BVXOR({1}[27:24],{2}[27:24]));\n".format(p, r, f)
        command += "ASSERT({0}[63:60] = BVXOR({1}[31:28],{2}[31:28]));\n".format(p, r, f)

        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(s)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(w)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(f)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(r)

        #Complete Feistel operation
        command += "ASSERT({0}[3:0]   = {1}[35:32]);\n".format(p, x_out)	#0 -> 8
        command += "ASSERT({0}[7:4]   = {1}[39:36]);\n".format(p, x_out)	#1 -> 9
        command += "ASSERT({0}[11:8]  = {1}[43:40]);\n".format(p, x_out)	#2 -> 10
        command += "ASSERT({0}[15:12] = {1}[47:44]);\n".format(p, x_out) 	#3 -> 11
        command += "ASSERT({0}[19:16] = {1}[51:48]);\n".format(p, x_out)	#4 -> 12
        command += "ASSERT({0}[23:20] = {1}[55:52]);\n".format(p, x_out)	#5 -> 13
        command += "ASSERT({0}[27:24] = {1}[59:56]);\n".format(p, x_out)	#6 -> 14
        command += "ASSERT({0}[31:28] = {1}[63:60]);\n".format(p, x_out)	#7 -> 15

        command += "ASSERT({0}[35:32] = {1}[3:0]);\n".format(p, x_out)	    #8 -> 0
        command += "ASSERT({0}[39:36] = {1}[7:4]);\n".format(p, x_out)	    #9 -> 1
        command += "ASSERT({0}[43:40] = {1}[11:8]);\n".format(p, x_out)	    #10 -> 2
        command += "ASSERT({0}[47:44] = {1}[15:12]);\n".format(p, x_out)	#11 -> 3
        command += "ASSERT({0}[51:48] = {1}[19:16]);\n".format(p, x_out)	#12 -> 4
        command += "ASSERT({0}[55:52] = {1}[23:20]);\n".format(p, x_out)	#13 -> 5
        command += "ASSERT({0}[59:56] = {1}[27:24]);\n".format(p, x_out)	#14 -> 6
        command += "ASSERT({0}[63:60] = {1}[31:28]);\n".format(p, x_out)	#15 -> 7


        stp_file.write(command)
        return


    def getSbox(self):
        #Returns sBox - Required for boomerang search
        sBox = [0xE, 9, 0xF, 0, 0xD, 4, 0xA, 0xB, 1, 2, 8, 3, 7, 6, 0xC, 5]
        return sBox

    def getSboxSize(self):
        #Returns sBox size - Required for boomerang search
        return 4
    
    def getPerm(self):
        #Returns permutation pattern - Required for boomerang search
        perm = [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7]
        return perm
    
    def getDesign(self):
        #Returns design paradigm ("gfn", "spn", "arx") - Required for boomerang search
        return "feistel"
