import socket
import time
from threading import Thread
import DES
import desHelper as DH
import random
import sys

KDC_SHARED_KEY = None # Key generated from the diffie-hellman that KDC knows
MY_ID = None

#Generates a key for the newly connected user
def generateKey():
    key = ''
    for i in range(10):
        key += str(random.randint(0,1))

    return int(key,2)

#Identical to generate key, but does not change it to an int
def generateNonce():
    return bin(generateKey())[2:]

#Generates an 8 bit nonce for the NS protocol's verification step 5
def generateTestNonce():
    nonce = ''
    for i in range(8):
        nonce += str(random.randint(0,1))

    return nonce

#Can be called to give the user instructions on what actions they may take
def printInstructions():
    print("Type 'Talkto' to speak with another user\n"+
        "Type 'List' to list other users connected to the server\n"+
        "Type 'Wait' to wait for another user to connect to you\n"+
        "Enter 'Quit' to exit")

#The client-side part of DH, check server.py for explanation on function
def diffie(kdc, PRIVATE_KEY):
    #Getting the public p and g from the KDC
    (PUBLIC_P, PUBLIC_G, MY_ID) = kdc.recv(1024).decode("utf8").split("|")
    PUBLIC_P = int(PUBLIC_P)
    PUBLIC_G = int(PUBLIC_G)

    #Waiting for Server to send it's first part of DH. Converts it into an int to be used later
    kdc_firstStep = int(kdc.recv(1024).decode("utf8").rstrip())
    
    #Performing the first step of DH for the client now, and sending it to the kdc
    client_firstStep = (PUBLIC_G ** PRIVATE_KEY) % PUBLIC_P
    kdc.send(str(client_firstStep).encode())

    sharedKey = (kdc_firstStep ** PRIVATE_KEY) % PUBLIC_P

    print("Finished Diffie-Hellman.")
    return bin(sharedKey)[2:].zfill(10), MY_ID

#Performs the Needham-Schroeder Protocol
def needhamSchroeder(kdc):
    #Beginning by verifying requested ID is valid
    valid = kdc.recv(1024).decode("utf8")
    if valid != "valid":
        print("Invalid ID requested!")
    else:
        #First step of Needham Schroeder is skipped in this function, as it is handled
        #by inputting 'talkto'

        aPackage = kdc.recv(1024).decode("utf8")

        decodedA = DH.runDecryption(aPackage, KDC_SHARED_KEY)

        #gathering the sessionkey and other things from string
        sessionKey = decodedA[:10]
        bID = decodedA[10:130]
        bID = DH.text_from_bits(bID)
        Nonce2 = decodedA[130:140]

        #This is the still encrypted package with B's needed info inside
        bPacket = decodedA[140:]

        #Now setting up this client as the host of a connection with the client
        mySocket = socket.socket()
        try:
            mySocket.bind(("127.0.0.1",5000))
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()

        #Waiting for the other to connect
        print("Waiting for connection...")
        mySocket.listen(1)
        conn, addr = mySocket.accept()
        print ("Connection from: " + str(addr))

        #Now that we are connected to B, we verify they are correct by sending them
        #their encrypted envelope.
        conn.send(bPacket.encode())

        testingNonce = conn.recv(1024).decode()
        nonce = DH.runDecryption(testingNonce, sessionKey)

        #Performing our arbitrary f(x) on the nonce, subtract 1 from nonce
        returningNonce = bin(int(nonce, 2)-1)[2:].zfill(8)
        encryptedReturn = DH.runEncryption(returningNonce, sessionKey)
        conn.send(encryptedReturn.encode())
        
        print("Sent verification to other user. Waiting for confirmation.")

        result = conn.recv(1024).decode()
        if result == "verified":
            '''
            This section is functionally identical to my homework 1 chatroom implementation
            Once the two are verified, they chat securely through this until one decides to quit
            This chat session uses the session key as it's encryption
            '''
            while True:
                data = conn.recv(1024).decode()

                #Conditionals to decide when to kill the server
                if not data:
                    break
                if data == 'q':
                    print("Client has ended the session.")
                    break

                #print ("Encrypted text received: " + str(data))

                #Decrypts the encrypted text from the user
                decryptedBinary = DH.runDecryption(data, sessionKey)
                output = DH.text_from_bits(decryptedBinary)

                print("\nDecrypted text: " + output)
            
                #Now it is the server's turn to send an encrypted message to the user!
                inputString = input("Enter the message you wish to encrypt:\n -> ")

                #If the server wants to quit, type q to break the loop
                if inputString == "q":
                    conn.send('q'.encode())
                    break
                else:
                    #Converting inital string to binary
                    inputString = DH.text_to_bits(inputString)

                    #Takes the binary representation of our text, splits it into 8 bit chunks, and encrypts it
                    message = DH.runEncryption(inputString, sessionKey)

                    #Sends the encrypted text back to the user
                    conn.send(message.encode())
            conn.close()
        #If Needham schroeder fails, then exit from the server entirely.
        else:
            print("Unable to verify. Exiting server.\n\n")
            conn.close()
            sys.exit()        

        print("\n\nWelcome back to the main server.")
        printInstructions()
        return

def receiveConnection(host, port):
    mySocket = socket.socket()
    mySocket.connect(("127.0.0.1",5000))

    print("Connected to another user.")

    #Now we will receive the info from the other user to get the session key
    encryptedInfo = mySocket.recv(1024).decode("utf8")

    #We decrypt that package to gather our session key and the ID of A
    decrypted = DH.runDecryption(encryptedInfo, KDC_SHARED_KEY)

    #Only take the session key and id out, nonce is no longer useful
    sessionKey = decrypted[:10]
    aID = decrypted[10:142]

    #Generate a new nonce to test A with, expecting nonce-1 back
    testingNonce = generateTestNonce()
    encryptedNonce = DH.runEncryption(testingNonce, sessionKey)
    mySocket.send(encryptedNonce.encode())

    #Waiting for A to process
    aVal = mySocket.recv(1024).decode()
    result = DH.runDecryption(aVal, sessionKey)

    #Printing to the user what the other returned
    print("Expected result: ", int(testingNonce,2)-1)
    print("Result from user: ", int(result,2))

    if int(result,2) == int(testingNonce,2)-1:
        print("Needham-Schroeder complete. Other user verified. Opening secure chatroom.")
        mySocket.send("verified".encode())
        
        while True:
            inputString = input("\nEnter the message you wish to encrypt:\n -> ")

            #Exit the server if the command is 'q'
            if inputString == 'q':
                break

            #Converting inital string to binary
            inputString = DH.text_to_bits(inputString)

            #Takes the binary representation of our text, splits it into 8 bit chunks, and encrypts it
            message = DH.runEncryption(inputString, sessionKey)

            #Sends the encrypted text to the server
            mySocket.send(message.encode())

            print("Waiting for server response...")

            data = str(mySocket.recv(1024).decode())

            if data == 'q':
                print("Server has ended the session.")
                quit(1)

            #print ('Encrypted text received from server: ' + data)

            #Takes the encrypted binary and turns it back to plaintext
            output = DH.text_from_bits(DH.runDecryption(data, sessionKey))

            print ('\nDecrypted text: ' + output)
        mySocket.close()
    else:
        print("Unable to verifiy the indentity of the other user. Exiting server.\n")
        mySocket.send("no".encode())
        mySocket.close()
        sys.exit()


def main():
    global KDC_SHARED_KEY
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 7005

    #Generating a secret key that only the client can know
    PRIVATE_KEY = generateKey()

    try:
        soc.connect((host, port))

        #Runs the Diffie-Hellman as soon as the connection is established
        KDC_SHARED_KEY, MY_ID = diffie(soc, PRIVATE_KEY)
    except:
        print("Connection error")
        sys.exit()

    print(soc.recv(1024).decode("utf8"))

    printInstructions()

    while True:
        message = input(" -> ").lower()
        #If the message wants to start needham schroeder, message must be changed to the correct format
        if "talkto" in message:
            messageArray = message.split()
            message = "talkto|" + MY_ID + messageArray[1] + generateNonce()

        soc.sendall(message.encode("utf8"))

        if message == "quit":
            break
        #Prints out all of the currently connected users to the client
        elif message == "list":
            users = soc.recv(1024).decode("utf8")
            print(users)
        #Attempts to connect to the user the client requested
        elif "talkto|" in message:
            needhamSchroeder(soc)
        #Used to wait for another user to connect to you
        elif message == "wait":
            print("Waiting to be connected to...")

            notConnected = True
            while notConnected:
                #Receiving server messages and checking their contents
                serverMessage = soc.recv(1024).decode("utf8")
                if "INCOMING" in serverMessage:
                    aIP = serverMessage.split("|")
                    aPort = aIP[1]
                    aIP = aIP[0]
                    notConnected = False

                    #Delay a second to ensure the other client has time to set up socket
                    time.sleep(.5)
                    receiveConnection(aIP, aPort)

        if soc.recv(1024).decode("utf8") == "-":
            pass        # null operation

            


    soc.send('QUIT'.encode())

if __name__ == "__main__":
    main()