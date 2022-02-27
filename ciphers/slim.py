'''
Created on Nov 3, 2021

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class Slim(AbstractCipher):
    """
    Represents the differential behaviour of Slim and can be used
    to find differential characteristics for the given parameters.
    """

    name = "slim"

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
            # x = input (32), s = S-Box output (16), f = output of F function after permutation (16)
            #p = swap 32-bit blocks (32)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            f = ["F{}".format(i) for i in range(rounds)]
            s = ["S{}".format(i) for i in range(rounds)]
            p = ["p{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupLBlockSRound(stp_file, x[i], s[i], p[i], f[i], x[i+1], 
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

    def setupLBlockSRound(self, stp_file, x_in, s, p, f, x_out, w, wordsize):
        """
        Model for differential behaviour of one round SLIM
        """
        command = ""

        # Substitution Layer
        slim_sbox = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]
        for i in range(4):
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
            command += stpcommands.add4bitSbox(slim_sbox, variables)

        # Permutation Layer
        # Input     0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15 
        # Output    7   13  1   8   11  14  2   5   4   10  15  0   3   6   9   12
        command += "ASSERT({0}[0:0] = {1}[7:7]);\n".format(s, f)
        command += "ASSERT({0}[1:1] = {1}[13:13]);\n".format(s, f)
        command += "ASSERT({0}[2:2] = {1}[1:1]);\n".format(s, f)
        command += "ASSERT({0}[3:3] = {1}[8:8]);\n".format(s, f)
        
        command += "ASSERT({0}[4:4] = {1}[11:11]);\n".format(s, f)
        command += "ASSERT({0}[5:5] = {1}[14:14]);\n".format(s, f)
        command += "ASSERT({0}[6:6] = {1}[2:2]);\n".format(s, f)
        command += "ASSERT({0}[7:7] = {1}[5:5]);\n".format(s, f)
        
        command += "ASSERT({0}[8:8] = {1}[4:4]);\n".format(s, f)
        command += "ASSERT({0}[9:9] = {1}[10:10]);\n".format(s, f)
        command += "ASSERT({0}[10:10] = {1}[15:15]);\n".format(s, f)
        command += "ASSERT({0}[11:11] = {1}[0:0]);\n".format(s, f)
        
        command += "ASSERT({0}[12:12] = {1}[3:3]);\n".format(s, f)
        command += "ASSERT({0}[13:13] = {1}[6:6]);\n".format(s, f)
        command += "ASSERT({0}[14:14] = {1}[9:9]);\n".format(s, f)
        command += "ASSERT({0}[15:15] = {1}[12:12]);\n".format(s, f)

        #Feistel structure
        command += "ASSERT({0}[3:0] = {1}[3:0]);\n".format(x_in, p)
        command += "ASSERT({0}[7:4] = {1}[7:4]);\n".format(x_in, p)
        command += "ASSERT({0}[11:8] = {1}[11:8]);\n".format(x_in, p)
        command += "ASSERT({0}[15:12] = {1}[15:12]);\n".format(x_in, p)

        command += "ASSERT({0}[19:16] = BVXOR({1}[19:16],{2}[3:0]));\n".format(p, x_in, f)
        command += "ASSERT({0}[23:20] = BVXOR({1}[23:20],{2}[7:4]));\n".format(p, x_in, f)
        command += "ASSERT({0}[27:24] = BVXOR({1}[27:24],{2}[11:8]));\n".format(p, x_in, f)
        command += "ASSERT({0}[31:28] = BVXOR({1}[31:28],{2}[15:12]));\n".format(p, x_in, f)

        command += "ASSERT(0x0000 = {0}[31:16]);\n".format(s)
        command += "ASSERT(0x0000 = {0}[31:16]);\n".format(w)
        command += "ASSERT(0x0000 = {0}[31:16]);\n".format(f)


        #Swap left and right
        command += "ASSERT({0}[3:0]   = {1}[19:16]);\n".format(p, x_out)	#0 -> 4
        command += "ASSERT({0}[7:4]   = {1}[23:20]);\n".format(p, x_out)	#1 -> 5
        command += "ASSERT({0}[11:8]  = {1}[27:24]);\n".format(p, x_out)	#2 -> 6
        command += "ASSERT({0}[15:12] = {1}[31:28]);\n".format(p, x_out) 	#3 -> 7

        command += "ASSERT({0}[19:16] = {1}[3:0]);\n".format(p, x_out)	    #4 -> 0
        command += "ASSERT({0}[23:20] = {1}[7:4]);\n".format(p, x_out)	    #5 -> 1
        command += "ASSERT({0}[27:24] = {1}[11:8]);\n".format(p, x_out)	    #6 -> 2
        command += "ASSERT({0}[31:28] = {1}[15:12]);\n".format(p, x_out)	#7 -> 3


        stp_file.write(command)
        return