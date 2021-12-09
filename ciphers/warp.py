'''
Created on Sep 24, 2021

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class WarpCipher(AbstractCipher):
    """
    Represents the differential behaviour of Warp and can be used
    to find differential characteristics for the given parameters.
    """

    name = "warp"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for WARP with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% WARP w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = input, s = S-Box layer output, p = permutation layer input
            x = ["X{}".format(i) for i in range(rounds + 1)]
            s = ["S{}".format(i) for i in range(rounds)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupWarpRound(stp_file, x[i], s[i], p[i], x[i+1], 
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


    def setupWarpRound(self, stp_file, x_in, s, p, x_out, w, wordsize):
        """
        Model for differential behaviour of one round WARP
        """
        command = ""

        # Substitution Layer
        warp_sbox = [0xC, 0xA, 0xD, 3, 0xE, 0xB, 0xF, 7, 8, 9, 1, 5, 0, 2, 4, 6]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(x_in, 8*i + 3),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 2),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 1),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 0),
                         "{0}[{1}:{1}]".format(s, 4*i + 3),
                         "{0}[{1}:{1}]".format(s, 4*i + 2),
                         "{0}[{1}:{1}]".format(s, 4*i + 1),
                         "{0}[{1}:{1}]".format(s, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(warp_sbox, variables)

        #Feistel structure
        command += "ASSERT({0}[3:0] = {1}[3:0]);\n".format(x_in, p)
        command += "ASSERT({0}[11:8] = {1}[11:8]);\n".format(x_in, p)
        command += "ASSERT({0}[19:16] = {1}[19:16]);\n".format(x_in, p)
        command += "ASSERT({0}[27:24] = {1}[27:24]);\n".format(x_in, p)
        command += "ASSERT({0}[35:32] = {1}[35:32]);\n".format(x_in, p)
        command += "ASSERT({0}[43:40] = {1}[43:40]);\n".format(x_in, p)
        command += "ASSERT({0}[51:48] = {1}[51:48]);\n".format(x_in, p)
        command += "ASSERT({0}[59:56] = {1}[59:56]);\n".format(x_in, p)

        command += "ASSERT({0}[67:64] = {1}[67:64]);\n".format(x_in, p)
        command += "ASSERT({0}[75:72] = {1}[75:72]);\n".format(x_in, p)
        command += "ASSERT({0}[83:80] = {1}[83:80]);\n".format(x_in, p)
        command += "ASSERT({0}[91:88] = {1}[91:88]);\n".format(x_in, p)
        command += "ASSERT({0}[99:96] = {1}[99:96]);\n".format(x_in, p)
        command += "ASSERT({0}[107:104] = {1}[107:104]);\n".format(x_in, p)
        command += "ASSERT({0}[115:112] = {1}[115:112]);\n".format(x_in, p)
        command += "ASSERT({0}[123:120] = {1}[123:120]);\n".format(x_in, p)

        command += "ASSERT({0}[7:4] = BVXOR({1}[7:4],{2}[3:0]));\n".format(p, x_in, s)
        command += "ASSERT({0}[15:12] = BVXOR({1}[15:12],{2}[7:4]));\n".format(p, x_in, s)
        command += "ASSERT({0}[23:20] = BVXOR({1}[23:20],{2}[11:8]));\n".format(p, x_in, s)
        command += "ASSERT({0}[31:28] = BVXOR({1}[31:28],{2}[15:12]));\n".format(p, x_in, s)
        command += "ASSERT({0}[39:36] = BVXOR({1}[39:36],{2}[19:16]));\n".format(p, x_in, s)
        command += "ASSERT({0}[47:44] = BVXOR({1}[47:44],{2}[23:20]));\n".format(p, x_in, s)
        command += "ASSERT({0}[55:52] = BVXOR({1}[55:52],{2}[27:24]));\n".format(p, x_in, s)
        command += "ASSERT({0}[63:60] = BVXOR({1}[63:60],{2}[31:28]));\n".format(p, x_in, s)
        
        command += "ASSERT({0}[71:68] = BVXOR({1}[71:68],{2}[35:32]));\n".format(p, x_in, s)
        command += "ASSERT({0}[79:76] = BVXOR({1}[79:76],{2}[39:36]));\n".format(p, x_in, s)
        command += "ASSERT({0}[87:84] = BVXOR({1}[87:84],{2}[43:40]));\n".format(p, x_in, s)
        command += "ASSERT({0}[95:92] = BVXOR({1}[95:92],{2}[47:44]));\n".format(p, x_in, s)
        command += "ASSERT({0}[103:100] = BVXOR({1}[103:100],{2}[51:48]));\n".format(p, x_in, s)
        command += "ASSERT({0}[111:108] = BVXOR({1}[111:108],{2}[55:52]));\n".format(p, x_in, s)
        command += "ASSERT({0}[119:116] = BVXOR({1}[119:116],{2}[59:56]));\n".format(p, x_in, s)
        command += "ASSERT({0}[127:124] = BVXOR({1}[127:124],{2}[63:60]));\n".format(p, x_in, s)

        command += "ASSERT(0x0000000000000000 = {0}[127:64]);\n".format(s)
        command += "ASSERT(0x0000000000000000 = {0}[127:64]);\n".format(w)

        #Permutation Layer
        # x  = [0,  1,  2,  3, 4,  5,  6, 7,  8, 9, 10, 11, 12, 13, 14, 15]
        # pi = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2,  3,  0, 25,  4, 23, 10]
        # 1 word = 4 bit
        command += "ASSERT({0}[3:0]   = {1}[127:124]);\n".format(p, x_out)	#0 -> 31
        command += "ASSERT({0}[7:4]   = {1}[27:24]);\n".format(p, x_out)	#1 -> 6
        command += "ASSERT({0}[11:8]  = {1}[119:116]);\n".format(p, x_out)	#2 -> 29
        command += "ASSERT({0}[15:12] = {1}[59:56]);\n".format(p, x_out) 	#3 -> 14
        command += "ASSERT({0}[19:16] = {1}[7:4]);\n".format(p, x_out)	    #4 -> 1
        command += "ASSERT({0}[23:20] = {1}[51:48]);\n".format(p, x_out)	#5 -> 12
        command += "ASSERT({0}[27:24] = {1}[87:84]);\n".format(p, x_out)	#6 -> 21
        command += "ASSERT({0}[31:28] = {1}[35:32]);\n".format(p, x_out)	#7 -> 8
        command += "ASSERT({0}[35:32] = {1}[111:108]);\n".format(p, x_out)	#8 -> 27
        command += "ASSERT({0}[39:36] = {1}[11:8]);\n".format(p, x_out)	    #9 -> 2
        command += "ASSERT({0}[43:40] = {1}[15:12]);\n".format(p, x_out)	#10 -> 3
        command += "ASSERT({0}[47:44] = {1}[3:0]);\n".format(p, x_out)		#11 -> 0
        command += "ASSERT({0}[51:48] = {1}[103:100]);\n".format(p, x_out)	#12 -> 25
        command += "ASSERT({0}[55:52] = {1}[19:16]);\n".format(p, x_out)	#13 -> 4
        command += "ASSERT({0}[59:56] = {1}[95:92]);\n".format(p, x_out)	#14 -> 23
        command += "ASSERT({0}[63:60] = {1}[43:40]);\n".format(p, x_out)	#15 -> 10

        # x  = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        # pi = [15, 22, 13, 30, 17, 28,  5, 24, 11, 18, 19, 16,  9, 20,  7, 26]
        # 1 word = 4 bit
        command += "ASSERT({0}[67:64] = {1}[63:60]);\n".format(p, x_out)	    #16 -> 15
        command += "ASSERT({0}[71:68] = {1}[91:88]);\n".format(p, x_out)	    #17 -> 22
        command += "ASSERT({0}[75:72] = {1}[55:52]);\n".format(p, x_out)	    #18 -> 13
        command += "ASSERT({0}[79:76] = {1}[123:120]);\n".format(p, x_out)	    #19 -> 30
        command += "ASSERT({0}[83:80] = {1}[71:68]);\n".format(p, x_out)	    #20 -> 17
        command += "ASSERT({0}[87:84] = {1}[115:112]);\n".format(p, x_out)	    #21 -> 28
        command += "ASSERT({0}[91:88] = {1}[23:20]);\n".format(p, x_out)	    #22 -> 5
        command += "ASSERT({0}[95:92] = {1}[99:96]);\n".format(p, x_out)	    #23 -> 24
        command += "ASSERT({0}[99:96] = {1}[47:44]);\n".format(p, x_out)	    #24 -> 11
        command += "ASSERT({0}[103:100] = {1}[75:72]);\n".format(p, x_out)	    #25 -> 18
        command += "ASSERT({0}[107:104] = {1}[79:76]);\n".format(p, x_out)	    #26 -> 19
        command += "ASSERT({0}[111:108] = {1}[67:64]);\n".format(p, x_out)	    #27 -> 16
        command += "ASSERT({0}[115:112] = {1}[39:36]);\n".format(p, x_out)	    #28 -> 9
        command += "ASSERT({0}[119:116] = {1}[83:80]);\n".format(p, x_out)	    #29 -> 20
        command += "ASSERT({0}[123:120] = {1}[31:28]);\n".format(p, x_out)	    #30 -> 7
        command += "ASSERT({0}[127:124] = {1}[107:104]);\n".format(p, x_out)	#31 -> 26


        stp_file.write(command)
        return
    
    def getSbox(self):
        #Returns sBox - Required for boomerang search
        sBox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
        return sBox

    def getSboxSize(self):
        #Returns sBox size - Required for boomerang search
        return 4
    
    def getPerm(self):
        #Returns permutation pattern - Required for boomerang search
        perm = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2,  3,  0, 25,  4, 23, 10, 15, 22, 13, 30, 17, 28,  5, 24, 11, 18, 19, 16,  9, 20,  7, 26]
        return perm
    
    def getDesign(self):
        #Returns design paradigm ("gfn", "spn", "arx") - Required for boomerang search
        return "gfn"
    
