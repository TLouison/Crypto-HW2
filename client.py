import socket
import time
from threading import Thread
import DES
import desHelper
import pickle
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
#Pads the string to 10 bits to ensure determinability
def generateNonce():
    return bin(generateKey())[2:]

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
        
        packageSplit = desHelper.splitBinary(aPackage)
        decodedA = desHelper.runDecryption(packageSplit, KDC_SHARED_KEY)
        aPlaintext = desHelper.rebuildString(decodedA)

        #gathering the sessionkey and other things from string
        sessionKey = aPlaintext[:10]
        bID = aPlaintext[10:130]
        bID = desHelper.text_from_bits(bID)
        Nonce2 = aPlaintext[130:140]

        #This is the still encrypted package with B's needed info inside
        bPacket = aPlaintext[140:]
        print(aPlaintext)

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

        

    return 1
    # decodedA = 

def receiveConnection(host, port):
    mySocket = socket.socket()
    mySocket.connect(("127.0.0.1",5000))

    print("Connected to this fucker")
    return


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

    print("Type 'Talkto' to speak with another user\n"+
        "Type 'List' to list other users connected to the server\n"+
        "Type 'Wait' to wait for another user to connect to you\n"+
        "Enter 'Quit' to exit")


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
                print(serverMessage)
                if "INCOMING" in serverMessage:
                    aIP = serverMessage.split("|")
                    aPort = aIP[1]
                    aIP = aIP[0]
                    notConnected = False

                    #Delay a second to ensure the other client has time to set up socket
                    time.sleep(.5)
                    receiveConnection(aIP, aPort)
                    # try:
                    #     Thread(target=receiveConnection, args=(aIP, aPort)).start()
                    # except:
                    #     print("Thread did not start.")
                    #     traceback.print_exc()
                print("loop reset")

        if soc.recv(1024).decode("utf8") == "-":
            pass        # null operation

            


    soc.send('QUIT'.encode())

if __name__ == "__main__":
    main()