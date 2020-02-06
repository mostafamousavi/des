# Simplified DES Encryption and Decryption
The very simplified DES algorithm:
The 16 bit message is devided to 2, 8bit blocks, named L0 and R0.
4 bits will be added to R0 by passing through the permut table. The result would be XORed by the 12 bits key.
The result would be devided to 2, 6 bits. The 1st 2 bits of each block indicates the column of the SBoxes and 
the last 4 bits indicates the row. So an 8 bit block is obtained from the SBoxes, by XORing that to the L0, the R1 
is found and L1 would be equal to R0.
The R1, L1 and a 1bit, left circular shifted key, are inputs to the next round. At the last Round, Ri+Li would
be the CipherText.
The Decyption is same as the above, except, it starts with the key that has been obtained from the last round 
of encryption and the key would be right shifted.  
