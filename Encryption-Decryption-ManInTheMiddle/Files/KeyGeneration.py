# -*- coding: utf-8 -*-
"""
Created on Mon Nov 26 21:00:45 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       Main.py is the starting point for the entire project

class KeyGeneration:
    #Contructor for KeyGeneration class
    #def __init__(self, keyFileName = "KEY.txt"):
    def __init__(self, objCommon):
        try:
            self.__limit = 9999999 #Upper limit for the keys, the value of generated keys will be in the range (2 <-> Upper Limit)
            self.common = objCommon
            self.__keysFileName = objCommon.keyFile
            
        except Exception as ex:
            print("An error occurred while initializing class KeyGeneration. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "limit: " + str(self.__limit) + ", keysFileName: " + str(self.__keysFileName) + ", common: " + str(self.common)
    
    #1. Generate and store Keys using Elgamal algorithm
    def GenerateAndStoreKeys(self):
        try:
            print("\nGenerating Keys...\n")
            keys = self.__GenerateKeys(self.__limit)
            self.common.WriteToFile(self.__keysFileName, keys)
            
        except Exception as ex:
            print("An error occurred in function KeyGeneration.GenerateAndStoreKeys while processing. Error: ", ex)
    
    #Generate Keys using Elgamal algorithm
    def __GenerateKeys(self, limitForPrime):
        try:
            #p
            randomPrime = self.common.GetRandomPrime(limitForPrime)
            
            #a
            secret = self.__GetSecret(randomPrime)
            
            #g
            primitveElement = self.__GetPrimitiveElement(secret)
            
            #c = g^a mod p        
            primitiveRaisedSecretModPrime = self.common.GetExponentiation(primitveElement, secret\
                                                              , randomPrime)
            
            #Public Key = (g, c, p)
            #Private Key = a
            dictionaryKeys = self.GetKeysDictionary(primitveElement, primitiveRaisedSecretModPrime \
                                               , randomPrime, secret)
            return dictionaryKeys
        
        except Exception as ex:
            print("An error occurred in function KeyGeneration.__GenerateKeys while processing. Error: ", ex)
    
    #Generate secret key
    def __GetSecret(self, randomPrimeValue):
        try:
            secret = self.common.GetRandomPrime(randomPrimeValue)
            while secret == randomPrimeValue:
                secret = self.common.GetRandomPrime(randomPrimeValue)
            return secret
        except Exception as ex:
            print("An error occurred in function KeyGeneration.__GetSecret while processing. Error: ", ex)
    
    #Generate Primitive element
    def __GetPrimitiveElement(self, secretKey):
        try:
            primitveElement = self.common.GetRandomPrime(secretKey)
            while primitveElement == secretKey:
                primitveElement = self.common.GetRandomPrime(secretKey)
            return primitveElement
        except Exception as ex:
            print("An error occurred in function KeyGeneration.__GetPrimitveElement while processing. Error: ", ex)
    
    #Get dictionary of keys
    def GetKeysDictionary(self, primitveElement, primitiveRaisedSecretModPrime, randomPrime, secret):
        try:
            #Public Key = (g, c, p)
            #Private Key = a
            publicKey = (primitveElement, primitiveRaisedSecretModPrime, randomPrime)
            print("Keys:\n Public Key (g,c,p):", publicKey, "\n", "Private Key:", secret)
            return {"PublicKey": publicKey, "PrivateKey": secret}
        except Exception as ex:
            print("An error occurred in function KeyGeneration.GetKeysDictionary while processing. Error: ", ex)
            
    #Read Reciver.txt file for keys or input values
    def ReadReceiversKeys(self, private):
        try:
            receiversKeys = []
            receiverFileName = self.__keysFileName
            if private is True:
                print("\nReading Private Key from file...")
            else:
                print("\nReading Public Key from file...")
            fileFound = self.common.FindFile(receiverFileName)
            if fileFound is True:
                fileContent = self.common.ReadFromFile(receiverFileName)
                result = self.common.IsDictionary(fileContent)
                
                if result is False:
                    print("\nThe file content is not in an expected format, please make sure it is not being modified.")
                    print("It is recommended to generate new keys.")
                else:
                    dictContent = result
                    setPublicKey = dictContent["PublicKey"]
                    
                    if len(setPublicKey) != 3:
                        print("\nThe Public Key in the file is not in an expected format, please make sure it is not being modified.")
                        print("It is recommended to generate new keys.")
                    else:
                        resultPrimitiveElement = self.common.IsInteger(setPublicKey[0])
                        resultPrimitiveRaisedSecretModPrime = self.common.IsInteger(setPublicKey[1])
                        resultRandomPrime = self.common.IsInteger(setPublicKey[2])
                        
                        if resultPrimitiveElement == False or resultPrimitiveRaisedSecretModPrime == False or resultRandomPrime == False:
                            print("\nThe Public Key in the file is not in an expected format, please make sure it is not being modified.")
                            print("It is recommended to generate new keys.")
                        else:
                            #Public Key = (g, resultRandomPrimec, p)
                            primitiveElement = resultPrimitiveElement
                            primitiveRaisedSecretModPrime = resultPrimitiveRaisedSecretModPrime
                            randomPrime = resultRandomPrime
                            
                            if private is True:
                                #Private Key
                                privateKey = dictContent["PrivateKey"]
                                result = self.common.IsInteger(privateKey)
                                if result is False:
                                    print("\nThe Private Key in the file is not in an expected format, please make sure it is not being modified.")
                                    print("It is recommended to generate new keys.")
                                else:
                                    receiversKeys = [primitiveElement, primitiveRaisedSecretModPrime, randomPrime, result]
                            else:
                                receiversKeys = [primitiveElement, primitiveRaisedSecretModPrime, randomPrime]
                    
            else:
                print("\nSince the Keys file is not found please generate the Keys using the Main Menu Option 1")
                print("Exiting to the main menu...")
            return receiversKeys
        except Exception as ex:
            print("An error occurred in function KeyGeneration.ReadReceiversKeys while processing. Error: ", ex)