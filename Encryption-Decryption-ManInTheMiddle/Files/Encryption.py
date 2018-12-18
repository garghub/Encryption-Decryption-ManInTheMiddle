# -*- coding: utf-8 -*-
"""
Created on Mon Nov 26 21:02:29 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       Main.py is the starting point for the entire project

from KeyGeneration import KeyGeneration

class Encryption:
    #Constructor for Encryption class
    #def __init__(self, encFileName = "ENC.txt"):
    def __init__(self, objCommon):
        try:
            self.common = objCommon
            self.__encMsgFileName = objCommon.encFile
            self.keyGeneration = KeyGeneration(objCommon)
        except Exception as ex:
            print("An error occurred while initializing class Encryption. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "common: " + str(self.common) + ", encMsgFileName: " + str(self.__encMsgFileName) + ", keyGeneration: " + str(self.keyGeneration)
    
    #2. Encrypt a message using Reciever's Public Key
    def EncryptMessage(self):
        try:
            #Read keys from file
            print()
            receiverKeys = self.keyGeneration.ReadReceiversKeys(False)
            if len(receiverKeys) > 0:
                primitiveElement = receiverKeys [0]
                primitiveRaisedSecretModPrime = receiverKeys[1]
                randomPrime = receiverKeys[2]
                    
                msg = randomPrime + 1
                inputValid = False
                while msg >= randomPrime or inputValid == False:
                    askUserEntry = "\nPlease enter the digits to be encrypted, smaller than " + str(randomPrime) + ": "
                    userEntered = input(askUserEntry)
                    result = self.common.IsInteger(userEntered)
                    
                    if result is False or result >= randomPrime:
                        print("\nInvalid Input Entered, please retry.")
                    else:
                        msg = result
                        inputValid = True
                
                encryptedMsgAndHeader = self.__GetEncryptedMessageAndHeader(
                        msg, primitiveElement, primitiveRaisedSecretModPrime, randomPrime)
                self.common.WriteToFile(self.__encMsgFileName, encryptedMsgAndHeader)
    
        except Exception as ex:
            print("An error occurred in function Encryption.EncryptMessage while processing. Error: ", ex)

    #Get Encrypted Message with Header to be sent to the receiver
    def __GetEncryptedMessageAndHeader(self, msg, primitiveElement, primitiveRaisedSecretModPrime, randomPrime):
        try:
            #Encrypted Message = message * (c^b mod p) mod p
            #Header = g^b mod p
            
            #b
            anotherRandom = self.common.GetRandomPrime(randomPrime);
            
            #c^b mod p
            primitiveRaisedSecRaisedRandomModPrime = self.common.GetExponentiation(primitiveRaisedSecretModPrime
                                                                       , anotherRandom, randomPrime)
            
            #Encrypted Message = message * (c^b mod p) mod p
            encryptedMessage = (msg * primitiveRaisedSecRaisedRandomModPrime) % randomPrime
            print("Generated Encrypted Message:", encryptedMessage)
            
            #Header = g^b mod p
            header = self.common.GetExponentiation(primitiveElement, anotherRandom, randomPrime)
            print("Generated Header:", header)
            
            return {"EncryptedMessage": encryptedMessage, "Header": header}
        
        except Exception as ex:
            print("An error occurred in function Encryption.__GetEncryptedMessageAndHeader while processing. Error: ", ex)
    
    #Read encrypted message file for values
    def ReadEncryptedMessageAndHeader(self):
        try:
            tupleEncMsgHead = ()
            encMsgFileName = self.__encMsgFileName
            print("\nReading Encrypted Message from file...")
            fileFound = self.common.FindFile(encMsgFileName)
            if fileFound is True:
                fileContent = self.common.ReadFromFile(encMsgFileName)
                result = self.common.IsDictionary(fileContent)
                
                if result is False:
                    print("\nThe file content is not in an expected format, please make sure it is not being modified.")
                else:
                    dictContent = result
                    encryptedMessage, header = dictContent["EncryptedMessage"], dictContent["Header"]
                    tupleEncMsgHead = (encryptedMessage, header)
            else:
                print("\nSince Encrypted Message file is not found please generate an encrypted message using Main Menu Option 2")
                print("Exiting to the main menu...")
            return tupleEncMsgHead
        except Exception as ex:
            print("An error occurred in function Encryption.ReadEncryptedMessageAndHeader while processing. Error: ", ex)