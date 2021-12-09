'''
Created on Oct 8, 2021

@author: jesenteh
'''

from parser import parsesolveroutput, stpcommands
from cryptanalysis import search
from config import (PATH_STP, PATH_BOOLECTOR, PATH_CRYPTOMINISAT, MAX_WEIGHT,
                    MAX_CHARACTERISTICS)

import subprocess
import random
import math
import os
import time
import sys

from fractions import gcd

def computeFeistelBoomerangDifferential(cipher, parameters):
    """
    Performs the complete boomerang differential search
    """
    #Check if required boomerang functions exist
    try:
        parameters["sbox"] = cipher.getSbox()
        parameters["sboxSize"] = cipher.getSboxSize()
        parameters["design"] = cipher.getDesign()
        parameters["perm"] = cipher.getPerm()
    except:
        print("----")
        print(sys.exc_info()[0], "occurred")
        print("Required boomerang functions do not exist")
        print("Please add getSbox, getSboxSize, getDesign in cipher definition")
        quit()
    start_time = time.time()
    createBCT(parameters, cipher)
    #while not search.reachedTimelimit(start_time, parameters["timelimit"]):
    print("----")
    print("Running initial boomerang search")
    print("----")
    #Finds the input and output differences of the entire boomerang then starts enumerating
    boomerangProb = feistelBoomerangTrailSearch(cipher, parameters, start_time)
    #Compute other boomerang trails for the given input and output differences
    while not search.reachedTimelimit(start_time, parameters["timelimit"]):
        prob = feistelBoomerangTrailSearch(cipher, parameters, start_time, boomerangProb)
        if prob == 99: #No more upper trails for the given input
            break
        elif prob == 0: #No lower trail found for the given limits
            print("Trying a different upper trail")
        else:
            boomerangProb = prob
            print("---")
            print("Improved boomerang probability = " + str(math.log(boomerangProb, 2)))
    print("\n----")
    print("Boomerang search completed for the following:")
    print("X0 = {}".format(parameters["boomerangVariables"]["X0"]))
    print("X{} = {}".format(parameters["lowertrail"], parameters["boomerangVariables"]["X{}".format(parameters["lowertrail"])]))
    print("Final boomerang probability = " + str(math.log(boomerangProb, 2)))
    print("----\n")
        
        #Clear the start/end points to start new boomerang search
        #parameters["boomerangVariables"].clear()

    return 0


def feistelBoomerangTrailSearch(cipher, parameters, timestamp, boomerangProb = 0):
    """
    Automatically enumerate boomerang differentials starting from a fixed upper trail
    """
    switchProb = 0
    alpha = ""
    beta = ""
    delta = ""
    gamma = ""
    upperCharacteristic = ""
    lowerCharacteristic = "" 
    diff_upper = 0
    diff_lower = 0
    start_time = timestamp
        
    #Search Upper Trail
    upperCharacteristic = boomerangTrail(cipher, parameters, timestamp, "upper")

    #Store output difference
    try:
        alpha = upperCharacteristic.getInputDiff()
        beta = upperCharacteristic.getOutputDiff()
    except:
        print("No characteristic found for the given limits")
        #If no more upper characteristics can be found, best boomerang differential for the given input has been found
        parameters["uweight"] = parameters["sweight"]
        parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
        parameters["blockedLowerCharacteristics"].clear()
        return 99
    upperWeight = parameters["sweight"] #Store optimal weight found for upper trail

    #Keep searching for another optimal lower characteristic, otherwise move on to different upper
    lowerWeight = parameters["lweight"]

    #Calculate weight limit of lower trails
    if parameters["lweight"] < parameters["wordsize"]/parameters["sboxSize"]:
        searchLimit = parameters["wordsize"]/parameters["sboxSize"] - parameters["lweight"]
    else:
        searchLimit = 1 #+1 means only find optimal lower trails 

    while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
        lowerWeight < parameters["lweight"]+searchLimit: 

        #Search Lower Trail
        lowerCharacteristic = boomerangTrail(cipher, parameters, timestamp, "lower", beta)

        #Store output difference
        try:
            gamma = lowerCharacteristic.getInputDiff()
            delta = lowerCharacteristic.getOutputDiff()
        except:
            print("No characteristic found for the given limits")
            parameters["blockedUpperCharacteristics"].append(upperCharacteristic)   
            parameters["blockedLowerCharacteristics"].clear()
            return 0
        lowerWeight = parameters["sweight"] #Store optimal weight found for lower trail

        #Block characteristics
        parameters["blockedLowerCharacteristics"].append(lowerCharacteristic)

        #Check for match
        switchProb = checkBCT(beta, gamma, parameters, cipher)

        #Successful switch has been found
        if switchProb != 0: 
            #Fix starting point if it has not been set in boomerang Variables
            if "X0" not in parameters["boomerangVariables"]:
                parameters["boomerangVariables"]["X0"] = alpha
                print("Fixed X0 in boomerang to {}".format(parameters["boomerangVariables"]["X0"]))
                print("----")
            #Fix end point if it has not been set in boomerang Variables
            if "X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"]:
                parameters["boomerangVariables"]["X{}".format(parameters["lowertrail"])] = delta
                print("Fixed X{} in boomerang to {}".format(parameters["lowertrail"], parameters["boomerangVariables"]["X{}".format(parameters["lowertrail"])]))
                print("----")
            #Perform clustering for upper if not done, then cluster lower
            while not search.reachedTimelimit(start_time, parameters["timelimit"]) and diff_upper == 0:
                diff_upper = boomerangDifferential(cipher, parameters, alpha, beta, upperWeight, timestamp, "upper")
            diff_lower = 0
            while not search.reachedTimelimit(start_time, parameters["timelimit"]) and diff_lower == 0:
                diff_lower = boomerangDifferential(cipher, parameters, gamma, delta, lowerWeight, timestamp, "lower")

            if search.reachedTimelimit(start_time, parameters["timelimit"]):
                return 99
            
            boomerangProb += diff_upper*diff_upper*diff_lower*diff_lower*switchProb
            print("Found boomerang trail: {}, {}, {}".format(math.log(diff_upper, 2), math.log(diff_lower, 2),math.log(switchProb, 2)))
            print("Boomerang probability: {}".format(math.log(boomerangProb, 2)))
            print("----")
        else:
            print("Invalid switch, search for new boomerang differential")
            print("----")
   
    #After searching for all possible optimal lower trails for the given upper trail, block upper trail
    print("Completed trail search with boomerang probability of {}".format(math.log(boomerangProb, 2)))
    #Block upper trail to find another upper trail
    parameters["blockedUpperCharacteristics"].append(upperCharacteristic)
    #Clear lower trails because the same lower trails can be matched to a different upper trail
    parameters["blockedLowerCharacteristics"].clear()
    parameters["uweight"] = upperWeight
    return boomerangProb


def boomerangTrail(cipher, parameters, timestamp, boomerangFace="upper", switchInput=""):
    """
    Search top or bottom trail (characteristic) of a boomerang
    """
    #Set parameters for targeted boomerang face
    if (boomerangFace == "upper"):
        weight = "uweight"
        fixedPoint = "X0"
        trail = "uppertrail"
        block = "blockedUpperCharacteristics"
        beta = ""
    else:
        weight = "lweight"
        fixedPoint = "X{}".format(parameters["lowertrail"])
        trail = "lowertrail"
        block = "blockedLowerCharacteristics"
        beta = switchInput

    print(("Starting search for characteristic with minimal weight for {} trail\n"
           "{} - Rounds: {} Wordsize: {}".format( boomerangFace, 
                                                 cipher.name,
                                                 parameters[trail],
                                                 parameters["wordsize"])))
    print("---")
    start_time = timestamp

    #Set target weight for trail
    parameters["sweight"] = parameters[weight]
    characteristic = ""
    
    while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
        parameters["sweight"] < parameters["endweight"]:

        print("Weight: {} Time: {}s".format(parameters["sweight"],
                                            round(time.time() - start_time, 2)))

        # Construct problem instance for given parameters
        stp_file = "tmp/{}-{}{}-{}-{}.stp".format(boomerangFace, cipher.name,
                                         parameters["wordsize"], parameters[trail], timestamp)
        
        #Fix number of rounds
        parameters["rounds"] = parameters[trail]

        #Fix starting point if it has been set in boomerang Variables
        parameters["fixedVariables"].clear()
        if fixedPoint in parameters["boomerangVariables"]:
            parameters["fixedVariables"][fixedPoint] = parameters["boomerangVariables"][fixedPoint]
            print("Fixed {} to {}".format(fixedPoint, parameters["fixedVariables"][fixedPoint]))

        #Block characteristics and invalid switches
        parameters["blockedCharacteristics"].clear()
        parameters["blockedCharacteristics"] = parameters[block].copy()

        cipher.createSTP(stp_file, parameters)
        #Block invalid switches in the stp file
        if beta != "":
            print("Blocking invalid switching differences for {}".format(beta))
            blockInvalidSwitches(beta, parameters, stp_file)
        result = ""
        if parameters["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        characteristic = ""

        # Check if a characteristic was found
        if search.foundSolution(result):
            current_time = round(time.time() - start_time, 2)
            print("---")
            print(("{} Trail for {} - Rounds {} - Wordsize {} - "
                   "Weight {} - Time {}s".format(boomerangFace,
                                                 cipher.name,
                                                 parameters[trail],
                                                 parameters["wordsize"],
                                                 parameters["sweight"],
                                                 current_time)))
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters[trail])
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters[trail])
            characteristic.printText()
            print("----")
            break
        parameters["sweight"] += 1
        print("----")

    if parameters["sweight"] >= parameters["endweight"] and boomerangFace == "upper":
        print("Weight limit has been reached. Ending search.")
        quit()

    return characteristic


def boomerangDifferential(cipher, parameters, input, output, weight, timestamp, boomerangFace="upper"):
    """
    Perform clustering for one face of a boomerang differential
    """
    #Set parameters for targeted boomerang face. Maintained for consistency.
    if (boomerangFace == "upper"):
        trail = "uppertrail"
        limit = "upperlimit"
    else:
        trail = "lowertrail"
        limit = "lowerlimit"

    start_time = timestamp
    
    print("Cluster {} differential".format(boomerangFace))
    
    #Clear blocked characteristics
    parameters["blockedCharacteristics"].clear()

    #Setup search
    #rnd_string_tmp = '%030x' % random.randrange(16**30)
    diff_prob = 0
    boomerangProb = 1
    characteristics_found = 0
    sat_logfile = "tmp/satlog{}.tmp".format(timestamp)

    parameters["fixedVariables"].clear()
    parameters["fixedVariables"]["X0"] = input
    parameters["fixedVariables"]["X{}".format(parameters[trail])] = output  
    parameters["sweight"] = weight

    #TODO: Remove later
    print("XO - ", input)
    print("X{} -".format(parameters[trail]), output)

    #Fix number of rounds
    parameters["rounds"] = parameters[trail]

    #Search until optimal weight + wordsize/8
    while not search.reachedTimelimit(start_time, parameters["timelimit"]) and \
        parameters["sweight"] < weight+parameters["wordsize"]/parameters[limit]:

        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)

        stp_file = "tmp/{}{}-{}.stp".format(cipher.name, trail,timestamp)
        cipher.createSTP(stp_file, parameters)

        # Start solver
        sat_process = search.startSATsolver(stp_file)
        log_file = open(sat_logfile, "w")

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(parameters["sweight"]))

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            line = sat_process.stdout.readline().decode("utf-8")
            log_file.write(line)
            if "s SATISFIABLE" in line:
                solutions += 1
            if solutions % 100 == 0:
                print("\tSolutions: {}\r".format(solutions // 2), end="")

        log_file.close()
        print("\tSolutions: {}".format(solutions // 2))

        assert solutions == search.countSolutionsLogfile(sat_logfile)

        # The encoded CNF contains every solution twice
        solutions //= 2

        # Print result
        diff_prob += math.pow(2, -parameters["sweight"]) * solutions
        characteristics_found += solutions
        if diff_prob > 0.0:
            #print("\tSolutions: {}".format(solutions))
            print("\tTrails found: {}".format(characteristics_found))
            print("\tCurrent Probability: " + str(math.log(diff_prob, 2)))
            print("\tTime: {}s".format(round(time.time() - start_time, 2)))
        parameters["sweight"] += 1

    print("----")
    return diff_prob


def createBCT(parameters, cipher):
    """
    Create BCT or FBCT - Ensure that these functions are available in cipher model
    """
    s = parameters["sbox"]
    #Create FBCT
    if parameters["design"] == "gfn" or parameters["design"] == "feistel":
        print("Creating FBCT for {}".format(parameters["cipher"]))
        for Di in range(16):
            for Do in range(16):
                    for x in range(16):
                        diff = s[x]^s[x^Di]^s[x^Do]^s[x^Di^Do];
                        if diff == 0:
                            parameters["bct"][Di][Do]+=1
    #print BCT
    print("----")
    for x in range(16):
        for y in range(16):
            print(parameters["bct"][x][y], end='')
            print(", ", end='')
        print("")
    print("----")
    return


def blockInvalidSwitches(beta, parameters, stp_filename):
    """
    Add blocking constraints in stpfile to block invalid switches
    """
    with open(stp_filename, "r+", encoding = "utf-8") as stp_file:
        #Remove queries lines
        stp_file.seek(0, os.SEEK_END)
        pos = stp_file.tell() - 1
        while pos > 0 and stp_file.read(1) != "Q":
            pos -= 1
            stp_file.seek(pos, os.SEEK_SET)
        #pos -= 1
        if pos > 0:
            stp_file.seek(pos, os.SEEK_SET)
            stp_file.truncate()

        #For GFN like WARP or TWINE (Note: Cannot be used for LBLOCK)
        if parameters["design"] == "gfn":
            n = 0
            nibbles = int(parameters["wordsize"]/parameters["sboxSize"])
            for x in range(-1, -nibbles, -2):
                input = int(beta[x],16)
                #Check if input to BCT is nonzero
                if input != 0:
                    #Loop through all BCT outputs for the given input and put into fixedVariables for blocking
                    for output in range(16):
                        if parameters["bct"][input][output] == 0:
                            a = "X0[{0}:{1}]".format((parameters["perm"][n]*4)+3, parameters["perm"][n]*4)
                            b = "{}".format(hex(output))
                            blockVariableValue(stp_file, a, b)
                        #If this is the initial trail, only allow switching probability of 1 (not necessarily the best results)
                        if ("X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"] and parameters["bct"][input][output] != 16): 
                            a = "X0[{0}:{1}]".format((parameters["perm"][n]*4)+3, parameters["perm"][n]*4)
                            b = "{}".format(hex(output))
                            blockVariableValue(stp_file, a, b)
                n+=2
        #Lblock
        if parameters["design"] == "feistel":
            n = 0
            nibbles = int(parameters["wordsize"]/parameters["sboxSize"]/2)
            for x in range(-1, -nibbles, -1):
                input = int(beta[x],16)
                #Check if input to BCT is nonzero
                if input != 0:
                    #Loop through all BCT outputs for the given input and put into fixedVariables for blocking
                    for output in range(16):
                        if parameters["bct"][input][output] == 0:
                            a = "X0[{0}:{1}]".format((parameters["perm"][n]*4)+3, parameters["perm"][n]*4)
                            b = "{}".format(hex(output))
                            blockVariableValue(stp_file, a, b)
                        #If this is the initial trail, only allow switching probability of 1 (not necessarily the best results)
                        if ("X{}".format(parameters["lowertrail"]) not in parameters["boomerangVariables"] and parameters["bct"][input][output] != 16): 
                            a = "X0[{0}:{1}]".format((parameters["perm"][n]*4)+3, parameters["perm"][n]*4)
                            b = "{}".format(hex(output))
                            blockVariableValue(stp_file, a, b)
                n+=1

        #Ensure that beta is not equal to gamma
        blockVariableValue(stp_file, "X0", beta)
        stpcommands.setupQuery(stp_file)
    return


def checkBCT(beta, gamma, parameters, cipher):
    """
    Check BCT and calculate switching probability
    """
    switchProb = 1.0
    
    #For GFN like WARP or TWINE (Note: Cannot be used for LBLOCK)
    if parameters["design"] == "gfn":
        nibbles = int(parameters["wordsize"]/parameters["sboxSize"])
        for x in range(-1, -nibbles, -2):
            input = int(beta[x],16)
            #Calculate position after permutation
            pos = -parameters["perm"][(-x)-1]-1
            output = int(gamma[pos],16)

            if parameters["bct"][input][output] != 0:
                switchProb = switchProb * parameters["bct"][input][output]/(parameters["sboxSize"]*parameters["sboxSize"])
            else:
                return 0
    
    #For LBlock
    if parameters["design"] == "feistel":
        nibbles = int(parameters["wordsize"]/parameters["sboxSize"]/2)
        for x in range(-1, -nibbles, -1):
            input = int(beta[x],16)
            #Calculate position after permutation
            pos = -parameters["perm"][(-x)-1]-1
            output = int(gamma[pos],16)

            if parameters["bct"][input][output] != 0:
                switchProb = switchProb * parameters["bct"][input][output]/(parameters["sboxSize"]*parameters["sboxSize"])
            else:
                return 0

    return switchProb


def blockVariableValue(stpfile, a, b):
    """
    Adds an assert that a != b to the stp stpfile.
    """
    stpfile.write("\nASSERT(NOT({} = {}));\n".format(a, b))
    #print("ASSERT(NOT({} = {}));".format(a, b))
    return
