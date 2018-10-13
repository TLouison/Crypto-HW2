import DES

#Helper functions to run the encryption on strings longer than 8 bits
def runEncryption(inputList, mainkey):
    encryptedBinary = []

    newDES = DES.toyDES()

    for string in inputList:
        encryptedBinary.append( newDES.encryptText(string, mainkey) )

    return encryptedBinary

#Same as above but for decryption
def runDecryption(encryptedList, mainkey):
    decryptedBinary = []

    newDES = DES.toyDES()

    for string in encryptedList:
        decryptedBinary.append( newDES.decryptText(string, mainkey) )

    return decryptedBinary


#======================================================================================================
# FUNCTIONS TO CONVERT ASCII TEXT TO BINARY
# FOUND FROM THIS LINK: https://stackoverflow.com/questions/7396849/convert-binary-to-ascii-and-vice-versa
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'
#======================================================================================================


#Splits binary string into discrete chunks of 8 bits
def splitBinary(string):
    binary_list = []
    string8 = ""

    #Splitting the binary string into 8 bit sections
    for i in range(len(string)):
        string8 += string[i]

        if len(string8) == 8:
            binary_list.append(string8)
            string8 = ""

    if len(string8) < 8 and len(string8) > 0:
        while len(string8) < 8:
            string8 += "0"
        binary_list.append(string8)

    return binary_list

#Takes a list of binary strings and concatenates them in order into a single large string
def rebuildString(binaryList):
    master_string = ''

    for binary in binaryList:
        master_string += binary

    return master_string