# Cryptography Homework 2
Cryptography and Network Security Homework 2, theory and programming.

# Programming Homework
## Implementation Explanation
This program has two separate functions: the Diffe-Hellman (DH) key exchange and the Needham-Schroeder (NS) Protocol. When run, the program will automatically perform the DH key exchange, and store those values in the Key Distribution Center, which the server of this program is an analogue of. The server is then used once again, to perform the NS protocol. This part of the implementation takes some care to maneuver correctly. 
- First, one client must indicate that they want to connect to another user on the server. 
- Next, another client must indicate that they want to be connected to.
- Once the second client is connected to, the identity of the person who connected to them is verified by the NS protocol.
- Finally, once the identities of the two parties are verified, the two can communicate securely.

## Run the program
First, the server needs to be set up. This is as simple as calling ```python3 server.py```. Then, all that must be done is, in separate terminals, run ```client.py```. Each client is assigned a unqiue ID at their connection, and Diffie-Hellman will automatically be performed to gain a shared secret key between the new user and the KDC.

The instructions displayed on the terminal tell you what commands can be issued, but they will be explained more here (all commands are case insensitive):
- ```'talkto ID'``` allows the user to request a connection between themselves and another user.
- ```'list'``` will list out all currently connected users that are not the user who requested the list.
- ```'wait'``` causes the client to sit and wait for a user to request a connection to them.
- ```'quit'``` cleanly exits the server.

## Implementation challenges
The largest challenge for me by far was the networking aspect of this homework. I do not have a large amount of experience in network programming, as I have not taken NetProg or OpSys. Due to this, I began my multi-user server by using code found at this website: 
 ```https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/```
 From this, I heavily modified the code to perform all of the procotols required to run this program. 
 Along with this, I found issues with the threading library. I followed multiple guides and read the docs, but couldn't find resolutions to some issues I was having, including:
 - Randomly not making it through Diffie-Hellman
 - Sometimes having variables not be the value I set them as
 
I couldn't find a way to resolve these issues, so if the client freezes during Diffie-Hellman, or crashes during Needham-Schroeder, please ```Ctrl+C``` and try it again. It will work the majority of the time.

Finally, the largest implementation challenge I faced was with connecting A to B without having the KDC intervene in some way. While I know it is incorrect, I have the KDC send the connection information to B so that it can connect to A. In no way should the KDC be sending this information to B, but it was an implementation challenge I was unable to overcome. This does not change the security of the implementation though, as the attacker could not know the shared secret key of B, so they wouldn't get any meaningful information from intercepting this information. The lack of change in security is the only reason I felt implementing this in this way was acceptable, but in the future, and with more network programming experience, I would investigate a different way of approaching this issue.

## Computational Diffie-Hellman
### Assumptions
There were a few assumptions I made during the implementation of Diffie-Hellman:
- The small key size would not be a security issue
- The public values available are static and small, but are still secure
- Using simple integers as opposed to primitive polynomials is as valid a way to securely transmit the keys.
These assumptions are primarily based on the idea that any possible adversary has a computer not strong enough to just brute force the keys (which is overwhelmingly incorrect in modern times).

### Set-up
The set-up for this implementation of the Diffie-Hellman is extremely simple. Whenever a new client connects to the server, it will automatically perform the Diffie-Hellman protocol with that new user. The key generated from this process is then stored on the KDC server.

### Algebraic Constructions
Implementing computation Diffie-Hellman was a fairly straightforward task when using the integer, and not polynomial, based formulae. When each user connects to the server, the server generates a new random key, and then uses the global, public variables p and g to calculate A. A is then sent to the newly connected user, who performs the same actions to generate a B, and then sends that to the server. Now that both have the secret from the other, they individually raise the received value to the value of their just-generated key, and then mods that with the public p. This provides a shared secret between the two that is completely unknowable by a 3rd party.

## Needham-Schroeder Protocol
### Explanation of Math
The math for Needham-Schroeder is executed in five steps:
1. Send the ID of both the person requesting the communication and the person they wish to talk to, and a nonce to the KDC
2. The KDC then encrypts all of that information, concatenated and encrypted like so:
```Key_A[ Ks || IDb || N || Key_B[ Ks || IDa || N]]```
 This encrypted string is then sent back to the client that requested it
3. A then decrypts the string using it's Key_A, which now means it has the session key and B's ID. It then sends the part still encrypted with B's key to B.
4. B decrypts what A just sent, and now also has the session key and A's id. To verify A is legitimate, B now encrypts a nonce with the session key, and expects nonce-1 back from A.
5. A receives the encrypted nonce, decrypts it, subtracts 1, then re-encrypts it with the session key and sends it back to B for verification.
IF, after these 5 steps, the final nonce that B received is what it was expecting, the two clients will then connect to a secure chatroom that will use the shared session key to encrypt and decrypt all messages.

### Security from Replay Attacks
My implementation of Needham-Schroeder implements a modification of the protocol known as *Neuman 93*. This implements an extra nonce when the KDC sends the information back the the requesting user. This prevents replay attacks by adding randomness to the string, which in turn makes it incredibly computationally difficult to reverse.
