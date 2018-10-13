'''
DISCLAIMER: This code was based on this:
    https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/
It has been modified heavily to fit our purposes with the Diffie-Hellman key exchange
and Needham-Schroeder, however the basic socket server from this code was 
taken directly from the above linked website.
'''

import random
import DES
import desHelper
import socket
import sys
import traceback
from threading import Thread

PUBLIC_P = 23
PUBLIC_G = 5

def main():
    start_server()

#Defining a global dictionary to keep track of the users as they connect
connections = dict()

#Generates a key for the newly connected user
def generateKey():
    key = ''
    for i in range(10):
        key += str(random.randint(0,1))

    return int(key,2)

#Returns the peer name of the user that matches the id
def getUserByID(id):
    for value in connections.values():
        if id in value[0]:
            for conn in connections.keys():
                if (connections[conn][0] == id):
                    return conn
    return -1

#Performs the Computational Diffe-Hellman to generate a shared secret between the 
#server (KDC) And the new connection. Since not parallelized, broken into a sequence. 
#Each step will have the KDC perform it's calculations, then instruct the client to do the same
def diffie(conn):
    KDC_secret = generateKey()

    #First sends the public p and g to the client
    conn.send('{:}|{:}|{:}'.format(PUBLIC_P, PUBLIC_G, connections[conn.getpeername()][0]).encode())

    #Performs the first step of DH, where the KDC generates (g^A mod p) and sends it to client
    KDC_firstStep = (PUBLIC_G ** KDC_secret) % PUBLIC_P
    conn.send(str(KDC_firstStep).encode())

    #Waiting for Server to send it's first part of DH. Converts it into an int to be used later
    client_firstStep = int(conn.recv(1024).decode("utf8").rstrip())

    sharedKey = (client_firstStep ** KDC_secret) % PUBLIC_P
    print("Finished Diffie-Hellman with User {:}.\n".format(connections[conn.getpeername()][0]))
    return bin(sharedKey)[2:].zfill(10)


#Performs the Needham-Schroeder Protocol to connect user a to user b
def needhamSchroeder(conn, connectionInfo):
    aName = connectionInfo[:4]
    bName = connectionInfo[4:8]
    if getUserByID(bName) == -1 or aName == bName:
        conn.send("Invalid ID.".encode())
        return
    conn.send("valid".encode())

    #pulling the user information out of the talkto request
    #converting id's to binary and padding them to be length
    aID = desHelper.text_to_bits(getUserByID(aName)[0]+':'+str(getUserByID(aName)[1]))
    bID = desHelper.text_to_bits(getUserByID(bName)[0]+':'+str(getUserByID(bName)[1]))
    print("BID LENGTH: ", len(bID))
    nonce1 = connectionInfo[8:]

    #Create a new nonce to prevent replay attacks
    nonce2 = bin(random.randint(0,1023))[2:].zfill(10)

    #Generates a 10-bit session key
    sessionKey = bin(generateKey())[2:].zfill(10)

    #Creates the "envelope" that contains the Session Key and A's ID
    #This is encrypted with B's key
    bEnvelopeContents = desHelper.splitBinary(sessionKey + aID + nonce2)
    bEnvelope = desHelper.runEncryption(bEnvelopeContents, 
                                        connections[getUserByID(bName)][2])
    bEnvelope = desHelper.rebuildString(bEnvelope)

    #Creates the main "package" that contains the session key, B's id, the nonce, and the envelope
    #This is encrypted with A's key
    print("keyLen: ", len(sessionKey))
    print("bIDLen: ", len(bID))
    print("Nonce2LEn: ", len(nonce2))
    print("bEnvelopeLen: ", len(bEnvelope))
    aPackageContents = desHelper.splitBinary(sessionKey + bID + nonce2 + bEnvelope)
    aPackage = desHelper.runEncryption(aPackageContents, 
                                        connections[getUserByID(aName)][2])
    aPackage = desHelper.rebuildString(aPackage)

    #Sending the encrypted package to A
    conn.send(aPackage.encode())
    print("NS-Safe package sent.")
    sender = getUserByID(aName)
    connections[getUserByID(bName)][1].send(("INCOMING|" + sender[0] + ":" + "1234").encode())


#Prints out all available users that the requester can talk to
#If no other users are connected, it will tell the requester they are lonely
def printUsers(conn, user):
    userString = "Connected users:\n"
    for person in connections.keys():
        if person != user:
            userString += "UserID: {:}\n".format(connections[person][0])
    
    if len(connections.keys()) == 1:
        userString = "No other users are currently connected.\n"
    conn.send(userString.encode())


def start_server():
    #Setting host and port to local and non-used values, respectively
    host = "127.0.0.1"
    port = 7005

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   
    print("Socket created")

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(5)       # queue up to 5 requests
    print("Socket now listening...\n")

    #A counter used to assign IDs to newly connected users
    USER_ID = 1

    # infinite loop- do not reset for every requests
    while True:
        #Waits for a new user to connect to the server
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)

        #Defining each connection as the numbered order they connected in, and their key from DH.
        user = connection.getpeername()

        connections[user] = [str(USER_ID).zfill(4), connection, None] #Init as None since DH not done yet
        USER_ID += 1

        try:
            Thread(target=client_thread, args=(connection, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()
        
    soc.close()

def client_thread(connection, ip, port):
    is_active = True

    user = connection.getpeername()
    print("Performing Diffie-Hellman with User {:}.".format(int(connections[user][0])))
    #Performs the Diffie-Hellman with the most recently connected user, and returns the generated key
    connections[user][2] = diffie(connection)

    connection.send("Welcome, user {:}.\n".format(connections[user][0]).encode())

    while is_active:
        client_input = connection.recv(1024).decode("utf8")
        print("Processing the input received from client {:}".format(connections[user][0]))

        if "quit" in client_input:
            print("Client is requesting to quit")
            connection.close()
            print("Connection " + ip + ":" + port + " closed")
            #Removes the user from the dictionary of actively connected clients
            del connections[user]
            is_active = False
        elif "list" in client_input:
            printUsers(connection, user)
            connection.sendall("-".encode("utf8"))
        elif "talkto" in client_input:
            #Splitting the data into useful chunks
            connectionInfo = client_input.split("|")[1]
            needhamSchroeder(connection, connectionInfo)
            connection.sendall("-".encode("utf8"))
        else:
            print("Processed result: {}".format(client_input))
            connection.sendall("-".encode("utf8"))


if __name__ == "__main__":
    main()