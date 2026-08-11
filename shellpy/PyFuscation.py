#!/usr/bin/env python3

'''

 	PyFuscation.py
    This python3 script obfuscates powershell function, variable and parameters in an attempt to bypass AV blacklists

    The obfuscation engine itself lives in psobfuscator.py, shared with
    shellpy. It used to be duplicated here, and the two copies drifted apart.

'''

import os
import sys
import time
import shutil
from argparse import ArgumentParser
import banner
from psobfuscator import (
    printR, printG, printY, printP,
    PSconfigFile, wordList,
    loadReserved, removeJunk, useSED,
    findVARs, findCustomParams, findFUNCs,
)


def main():
    iFile = args.script

    printR("Obfuscating: " + iFile)
    ts = time.strftime("%m%d%Y_%H_%M_%S", time.gmtime())
    # dirname() is empty for a script in the current directory, which used to
    # build an absolute "/<timestamp>" path and fail with permission denied.
    oDir = os.path.join(os.path.dirname(args.script) or ".", ts)
    os.mkdir( oDir );
    oFile = os.path.join(oDir, ts + ".ps1")
    vFile = os.path.join(oDir, ts + ".variables")
    fFile = os.path.join(oDir, ts + ".functions")
    pFile = os.path.join(oDir, ts + ".parameters")
    shutil.copy(args.script, oFile)

    obfuVAR     = dict()
    obfuPARMS   = dict()
    obfuFUNCs   = dict()

    # Remove White space and comments
    removeJunk(oFile)

    # Obfuscate Variables
    if (args.var):
        obfuVAR = findVARs(iFile,vFile)
        useSED(obfuVAR, oFile)
        printP("Obfuscated Variables located  : " + vFile)

    # Obfuscate custom parameters
    if (args.par):
        obfuPARMS = findCustomParams(iFile, pFile, obfuVAR)
        useSED(obfuPARMS, oFile)
        printP("Obfuscated Parameters located : " + pFile)

    # Obfuscate Functions
    if (args.func):
        obfuFUNCs = findFUNCs(iFile, fFile)
        useSED(obfuFUNCs, oFile)

        # Print the Functions
        print("")
        print("Obfuscated Function Names")
        print("-------------------------")
        sorted_list=sorted(obfuFUNCs)
        for i in sorted_list:
            printG("Replaced " + i + " With: " + obfuFUNCs[i])
        print("")
        printP("Obfuscated Functions located  : " + fFile)

    printP("Obfuscated script located at  : " + oFile)
    return oFile

if __name__ == "__main__":

    if sys.version_info <= (3, 0):
        sys.stdout.write("This script requires Python 3.x\n")
        sys.exit(1)

    banner.banner()
    banner.title()

    parser = ArgumentParser()
    parser.add_argument("-f",   dest="func",    help="Obfuscate functions",     action="store_true")
    parser.add_argument("-v",   dest="var",     help="Obfuscate variables",     action="store_true")
    parser.add_argument("-p",   dest="par",     help="Obfuscate parameters",    action="store_true")
    parser.add_argument("--ps", dest="script",  help="Obfuscate powershell")

    args = parser.parse_args()

    # Powershell script
    if (args.script is None):
        parser.print_help()
        exit()
    else:
        # Check if the input file is valid:
        if not os.path.isfile(args.script):
            printR("Check File: " + args.script)
            exit()

    if not os.path.isfile(PSconfigFile):
        printR("Check PSconfig: " + PSconfigFile)
        exit()

    if not os.path.isfile(wordList):
        printR("Check wordList: " + wordList)
        exit()

    # Fails loudly here rather than silently obfuscating the reserved
    # powershell variables, which is what broke the generated scripts.
    loadReserved()

    main()
