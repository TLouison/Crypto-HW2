# Cryptography Homework 2
Cryptography and Network Security Homework 2, theory and programming.

# Programming Homework
## Implementation Explanation
This program has two separate functions: the Diffe-Hellman (DH) key exchange and the Needham-Schroeder (NS) Protocol. When run, the program will automatically perform the DH key exchange, and store those values in the Key Distribution Center, which the server of this program is an analogue of. The server is then used once again, to perform the NS protocol. This part of the implementation takes some care to maneuver correctly. 
- First, one client must indicate that they want to connect to another user on the server. 
- Next, another client must indicate that they want to be connected to.
- Once the second client is connected to, the identity of the person who connected to them is verified by the NS protocol.
- Finally, once the identities of the two parties are verified, the two can communicate securely.

In its' current state, my implementation does not properly verify the identity of the user that connects to the user that requested communication. This is due to my lack of experience with network programming, and will be fixed soon.

## Computational Diffie-Hellman
### Assumptions
There were a few assumptions I made during the implementation of Diffie-Hellman:
- The small key size would not be a security issue
- The public values available are static and small, but are still secure
- Using simple integers as opposed to primitive polynomials is as valid a way to securely transmit the keys.

### Set-up
The set-up for this implementation of the Diffie-Hellman is extremely simple. Whenever a new client connects to the server, it will automatically perform the Diffie-Hellman protocol with that new user. The key generated from this process is then stored on the KDC server.

### Algebraic Constructions
Implementing computation Diffie-Hellman was a fairly straightforward task when using the integer, and not polynomial, based formulae. When each user connects to the server, the server generates a new random key, and then uses the global, public vairables p and g to calculate A. A is then sent to the newly connected user, who performs the same actions to generate a B, and then sends that to the server. Now that both have the secret from the other, they individually raise the received value to the value of their just-generated key, and then mods that with the public p. This provides a shared secret between the two that is completely unknowable by a 3rd party.
