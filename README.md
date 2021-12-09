# CryptoSMT-Boomerang
New module for the CryptoSMT tool to support automatic boomerang search.
This repository also contains the codes for the related-key attack on WARP (warp-verification)

Instructions:
1. Install the CryptoSMT tool (https://github.com/kste/cryptosmt) - See installation.txt.
2. Copy all files from this repository into their respective folders. Some of the files include error fixes to existing files to support Feistel ciphers.
3. Run cryptosmt-boomerang.py instead of cryptosmt.py.
4. See the examples/warp10-9-boomerang.yaml to understand how to setup and run the boomerang search.
5. Sample execution:
```
    python3 cryptosmt-boomerang.py --input ./search/warp10-9-boomerang.yaml
```
7. To use the boomerang search for other ciphers, additional functions need to be added to the cipher definition. See ciphers/warp.py for examples:
```
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
```
