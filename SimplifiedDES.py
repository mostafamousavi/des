'''
The very simplified DES algorithm:
The Code is written by Python3
The 16 bit message is devided to 2, 8bit blocks, named L0 and R0.
4 bits will be added to R0 by passing through the permut table. The result would be XORed by the 12 bits key.
The result would be devided to 2, 6 bits. The 1st 2 bits of each block indicates the column of the SBoxes and 
the last 4 bits indicates the row. So an 8 bit block is obtained from the SBoxes, by XORing that to the L0, the R1 
is found and L1 would be equal to R0.
The R1, L1 and a 1bit, left circular shifted key, are inputs to the next round. At the last Round, Ri+Li would
be the CipherText.
The Decyption is same as the above, except, it starts with the key that has been obtained from the last round 
of encryption and the key would be right shifted.  
'''

class Encryption:


    #The permutation table, Shuffles the bits and adds 4 bits to have 12 bits to be xored by the key
    permut = [1,2,4,3,4,3,5,6,8,7,8,7]


    #Sboxes to find an 8 bit message from a 6 bit message
    S1Box = [['0110', '0001', '1010', '1001', '0101', '1111', '1011', '0111', '0011', '0000', '1110', '1100', '1101', '0010', '1000', '0100'],
             ['0001', '0000', '0111', '0011', '1101', '1110', '0010', '1010', '1001', '1100', '1000', '1111', '0110', '0100', '0101', '1011'],
             ['1100', '1101', '1000', '1011', '0000', '0111', '1111', '0101', '0011', '1001', '1010', '0100', '0110', '1110', '0001', '0010'],
             ['0111', '0010', '0000', '0101', '0011', '1101', '0001', '1111', '1011', '0100', '1010', '1001', '1100', '1000', '0110', '1110']]



    S2Box =[['1011', '0100', '1000', '0001', '0011', '1101', '1100', '1001', '0000', '0101', '1110', '0010', '1111', '0111', '1010', '0110'],
            ['0111', '1111', '1110', '0011', '1000', '1100', '1001', '0010', '0000', '1010', '0100', '0001', '0101', '0110', '1011', '1101'],
            ['1110', '1101', '1000', '0100', '0010', '1010', '0110', '1111', '0111', '1011', '0001', '1100', '0101', '0000', '1001', '0011'],
            ['1001', '0111', '1110', '1011', '1010', '1101', '0101', '0100', '0110', '0001', '0011', '1100', '1000', '0000', '1111', '0010']]


    def __init__(self,Rounds,Key):
        #Number of encryption rounds
        self.Rounds = Rounds
        #The Key
        self.Key = Key



    # To Circular left shift of bits which are in the form of an string 
    def rotl(self,num):
        num = num[1:]+num[:1]    
        return num



    # To Circular right shift of bits which are in the form of an string 
    def rotr(self,num):  
        num = num[-1]+num[:11]    
        return num




    #To Convert 2 strings to binaries and Bitwise XOR 
    def xor(self,str1,str2):
        return int(str1,2) ^ int(str2,2)




    #To split the 16 bits plaintext to 2 8 bit blocks
    def splitMessage(self,message):
        L = message[:8]
        R = message[8:]
        return L,R



    #To get the place of the Sbox items and extract the values from the Columns and rows
    def SBoxes(self, num, key):
        
        #convert to binary eliminate sign bit and add 0's to the left to be equal to the size of key, ie. 12 bits
        binStr = bin(num)[2:].zfill(len(key))
        #find the column and row indices of Sbox1
        S1ColIndx = str(binStr[:6])[:2]
        S1RowIndx = str(binStr[:6])[2:]
        #find the column and row indices of Sbox2
        S2ColIndx = str(binStr[6:])[:2]
        S2RowIndx = str(binStr[6:])[2:]
        #Get the corresponding value in the SBOX1
        s1 = self.S1Box[int(S1ColIndx,2)][int(S1RowIndx,2)]
        #Get the corresponding value in the SBOX2
        s2 = self.S2Box[int(S2ColIndx,2)][int(S2RowIndx,2)]
        #Retrun the Merged value
        return s1+s2
    



    #To Encrypt the plain_text and create the Cipher_text
    def Encrypt(self,message):     
        
        #key
        key = self.Key
        #rounds
        rnds = self.Rounds
        #left and right blocks of message
        L,Ri = self.splitMessage(message)
        
        #Takes care of the rounds
        while rnds > 0:
            #A list to store the permuted bits       
            permlist = []
            #adds the bits to permlist by getting their indices from the permut list
            for i in Encryption.permut:
                permlist.append(Ri[i-1])
            #E(Ri) gets list elements and store then as an string 
            EofRi = ''.join(permlist)
            #Xor the above E function with the key 
            ERixorK = self.xor(EofRi,key)
            #Using the SBoxes Method to get the value from the Sboxes
            sbox = self.SBoxes(ERixorK, key)     
            #Xor the value obtained from sboxes with Left 8bits block of message
            sboxXORl = self.xor(sbox,L)
            #Convert the above value to binary and eliminating 0b and adding 0's to the left
            R = bin(sboxXORl)[2:].zfill(len(L))
            #Li = Ri-1
            L = Ri 
            #Store the new value of R to Ri (in fact Ri-1 = Ri) to continue the iteration
            Ri = R
            #The key at the first iteration mustn't be shifted, That is why we keep an eye on it to be shifted one time less
            if rnds != 1:
                key = self.rotl(key)
            rnds -= 1
        #The final right and left blocks of Ciphertext and the key
        return R,L,key



    #To Decrypt the Cipher_Text and retrive the Plain_Text    
    def Decrypt(self,L,Ri,key):

        #rounds
        rnds = self.Rounds     

        #Takes care of the rounds
        while rnds > 0:
            #A list to store the permuted bits       
            permlist = []
            #adds the bits to permlist by getting their indices from the permut list
            for i in Encryption.permut:
                permlist.append(Ri[i-1])
            #E(Ri) gets list elements and store then as an string 
            EofRi = ''.join(permlist)
            #Xor the above E function with the key 
            ERixorK = self.xor(EofRi,key)
            #Using the SBoxes Method to get the value from the Sboxes
            sbox = self.SBoxes(ERixorK, key)     
            #Xor the value obtained from sboxes with Left 8bits block of message
            sboxXORl = self.xor(sbox,L)
            #Convert the above value to binary and eliminating 0b and adding 0's to the left
            R = bin(sboxXORl)[2:].zfill(len(L))
            #Li = Ri-1
            L = Ri 
            #Store the new value of R to Ri (in fact Ri-1 = Ri) to continue the iteration
            Ri = R
            #The key at the first iteration mustn't be shifted, That is why we keep an eye on it to be shifted one time less
            key = self.rotr(key)
            rnds -= 1
        #The final right and left blocks of Plaintext    
        return L,R



    #To separate and couple each 2 char and Convert them to binary to have 2*8 bits 
    #that is equal to the length of the plain-text in the algorithm
    def getMessage(self,message):

        #List to store the coupled binaries
        coupledList = []
        #Extracts Chars from the uppercase message and Converts each character to its binary equivalent  
        binMesList = [bin(ord(chara))[2:].zfill(8) for chara in message.upper()]
        #Checks if the number of list elements are even
        if len(binMesList) % 2 == 0:
            coupledList = [ x+y for x,y in zip(binMesList[0::2], binMesList[1::2])]
        else: #If not, adds 00100000 which is the binary equivalent of space at the end of messaege 
            binMesList.append('00100000')
            coupledList = [ x+y for x,y in zip(binMesList[0::2], binMesList[1::2])]
        return coupledList




    #To do the Encryption and Decryption using the above Methods
    def simplifiedDES(self,message):
        #Getting the message from user
        #message = input('Please Enter the plain_text: ')#must be uncommented to get the message from user  
        #Variables to store the strings that have been obtained from the lists      
        enc = ''
        dec = ''
        #Loop through the coupled binaries -the O/P of getMessage Method- and merge the blocks to get the Plaintext and Cyphertext 
        for coupledBins in self.getMessage(message): 
            #Store the right and left blocks of Ciphertext and the shifted key, obtained from the Encrypt()   
            R,L,K = self.Encrypt(coupledBins)
            #Concat right and left blocks of Ciphertext, separate every 8bits, Convert to Chars and store in enc  
            enc += ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(R+L)]*8))
            #Get the left and right bocks of Decrypted message, store in dL and dR
            dL,dR = self.Decrypt(R,L,K)
            #Concat right and left blocks of Plain-text, separate every 8bits, Convert to Chars and store in dec 
            dec += ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(dR+dL)]*8))
        return 'Cipher_text: ' + enc + ' \n PLain_Text: ' + dec


#To create an instance of the class and execute the simplifiedDES() Method
# encr = Encryption(5,'100111000011')#must be uncommented to get the message from user
# encr.simplifiedDES()#must be uncommented to get the message from user