import math
import SBox
import sys

_MAIN_KEY_ = ""

#============= S Boxes ==============
# S0
S0 = SBox.SBox(0, [[1, 0, 3, 2],
                   [3, 2, 1, 0],
                   [0, 2, 1, 3],
                   [3, 1, 3, 2]])

# S1
S1 = SBox.SBox(1, [[0, 1, 2, 3],
                   [2, 0, 1, 3],
                   [3, 0, 1, 0],
                   [2, 1, 0, 3]])

class toyDES:
    def __init__(self):
        return

    def encryptText(self, plaintext, mainkey):
        _MAIN_KEY_ = mainkey
        #Performing the initial permutation
        initial_permutation = self.initPermute(plaintext)

        #Breaking the 8-bits into a left and right key
        leftBits = initial_permutation[:4]
        rightBits = initial_permutation[4:]

        #Getting the K values from the main private key
        (K1,K2) = self.generateKs(_MAIN_KEY_)

        #If the operation type is 1, means encrypt text
        (new_left, new_right) = self.DES_Round(leftBits, rightBits, K1)     #First Round
        (finalLeft, finalRight) = self.DES_Round(new_left, new_right, K2)   #Second Round

        #Combining and finalizing permutations
        finalText = self.inversePermute(finalRight+finalLeft)
        return(finalText)

    def decryptText(self, plaintext, mainkey):
        _MAIN_KEY_ = mainkey
        #Performing the initial permutation
        initial_permutation = self.initPermute(plaintext)

        #Breaking the 8-bits into a left and right key
        leftBits = initial_permutation[:4]
        rightBits = initial_permutation[4:]

        #Getting the K values from the main private key
        (K1,K2) = self.generateKs(_MAIN_KEY_)

        #If the operation type is 1, means encrypt text
        (new_left, new_right) = self.DES_Round(leftBits, rightBits, K2)     #First Round
        (finalLeft, finalRight) = self.DES_Round(new_left, new_right, K1)   #Second Round

        #Combining and finalizing permutations
        finalText = self.inversePermute(finalRight+finalLeft)
        return(finalText)
   

    def DES_Round(self, leftKey, rightKey, k_val):
        #Running the F function with the right key
        newKey = self.F(rightKey, k_val)

        left_post_XOR = bin(int(leftKey,2)^int(newKey,2))[2:]
        while len(left_post_XOR) < 4:
            left_post_XOR = "0" + left_post_XOR

        newLeft = rightKey
        newRight = left_post_XOR
        return (newLeft, newRight)

    #Responsible for expanding the key, XORing it with a K value, then using the
    #SBoxes to create a new permutation of the input key
    def F(self, key, K_val):
        #Takes the key and expands it to 8 bits
        longKey = key[3] + key[0] + key[1] + key[2] + key[1] + key[2] + key[3] + key[0]

        #XORs the expanded key with the 8-bit k value
        post_XOR_key = bin(int(longKey,2)^int(K_val,2))[2:]

        #Appends 0s to the string until it is the right length again
        while len(post_XOR_key) < 8:
            post_XOR_key = "0" + post_XOR_key

        newLeft = post_XOR_key[0:4]
        newRight = post_XOR_key[4:]

        #Gathering information from the S Boxes to convert into 2-bit strings
        leftResult = S0.getResult(newLeft)
        rightResult = S1.getResult(newRight)

        #Turning the two 2-bit results into the new key
        newKey = leftResult + rightResult

        #Permutes the newKey into a new order
        newKey = newKey[1] + newKey[3] + newKey[2] + newKey[0]

        return(newKey)
        
    #Generate the K1 and K2 that are used in the F Function
    def generateKs(self, initialKey):
        #Permutes the initial key by what is shown on the lecture slides
        permutedKey = initialKey[2] + initialKey[4] + initialKey[1] + initialKey[6] + initialKey[3] + initialKey[9] + initialKey[0] + initialKey[8] + initialKey[7] + initialKey[5]
        leftKey = permutedKey[:5]
        rightKey = permutedKey[5:]

        #Creates the new keys that will be used for the 8bit keys
        newLeft = leftKey[1:] + leftKey[0]
        newRight = rightKey[1:] + rightKey[0] 
        K1 = self.pEightBox(newLeft, newRight)

        #Shifts left one more time in order to generate a different 8bit key
        newLeft = newLeft[1:] + newLeft[0]
        newRight = newRight[1:] + newRight[0] 
        K2 = self.pEightBox(newLeft, newRight)

        return(K1,K2)

    #Defines the permutation for the P8 box, transforms a 10-bit key into 8-bits
    def pEightBox(self, key1, key2):
        key = key1 + key2
        #Placing the bits into the required locations
        key8bit = key[5] + key[2] + key[6] + key[3] + key[7] + key[4] + key[9] + key[8]

        return(key8bit)

    #================================== Permutation Functions =================================
    #Takes the initial 8-bit text and permutes it into the order given in lecture 1.2 slides
    def initPermute(self, text):
        newKey = text[1] + text[5] + text[2] + text[0] + text[3] + text[7] + text[4] + text[6]
        return(newKey)

    #Runs the inverse of the initial permutation
    def inversePermute(self, text):
        newKey = text[3] + text[0] + text[2] + text[4] + text[6] + text[1] + text[7] + text[5]
        return(newKey)
    #==========================================================================================
    