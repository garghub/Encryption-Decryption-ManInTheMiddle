# -*- coding: utf-8 -*-
"""
Created on Mon Nov 26 21:04:15 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       Main.py is the starting point for the entire project

from KeyGeneration import KeyGeneration
from Encryption import Encryption

class Decryption:
    #Constructor for Decryption function
    def __init__(self, objCommon):
        try:
            self.common = objCommon
            self.keyGeneration = KeyGeneration(objCommon)
            self.encryption = Encryption(objCommon)
        except Exception as ex:
            print("An error occurred while initializing class Decryption. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "common: " + str(self.common) + ", keyGeneration: " + str(self.keyGeneration) + ", encryption: " + str(self.encryption)
    
    #3. Decrypt an encrypted message using your (Receiver's) Private Key
    def DecryptMessage(self):
        try:
            #Read Encrypted Message and Header from file
            tupleEncMsgHead = self.encryption.ReadEncryptedMessageAndHeader()
            
            if len(tupleEncMsgHead) > 0:
                #Read keys from file
                receiversKeys = self.keyGeneration.ReadReceiversKeys(True)
                if len(receiversKeys) > 0:
                    
                    encryptedMessage, header = tupleEncMsgHead[0], tupleEncMsgHead[1]
                    
                    #primitiveElement = receiversKeys[0]
                    #primitiveRaisedSecretModPrime = receiversKeys[1]
                    randomPrime = receiversKeys[2]
                    privateKey = receiversKeys[3]
            
                    #Calculating Header ^ PrivateKey Mod p
                    #where header = (g^b mod p)
                    #So, mathematically the formula can be written as (g^b mod p) ^a mod p
                    headerRaisedEncMsgModPrime = self.common.GetExponentiation(header, privateKey, randomPrime)
            
                    #Calculating inverse of Header ^ PrivateKey Mod p
                    invHeaderRaisedEncMsgModPrime = self.GetInverseModPrime (headerRaisedEncMsgModPrime, randomPrime)
            
                    decryptedMessage = (invHeaderRaisedEncMsgModPrime * encryptedMessage) % randomPrime
                    
                    print("\nDecrypted Original Message:", decryptedMessage)
                
        except Exception as ex:
            print("An error occurred in function Decryption.DecryptMessage while processing. Error: ", ex)
    
    #To perform extended euclidean to help find the inverse mod prime
    def PerformExtendedEuclidean(self, element, prime):
        try:
            if prime == 0:
               return [element, 1, 0]
    
            vals = self.PerformExtendedEuclidean(prime, element % prime)
            d = vals[0]
            a = vals[2]
            b = vals[1] - (element // prime) * vals[2]
            return [d, a, b]
        except Exception as ex:
            print("An error occurred in function Decryption.PerformExtendedEuclidean while processing. Error: ", ex)
    
    #To calculate Inverse of an element mod prime
    def GetInverseModPrime(self, element, prime):
        try:
            vals = self.PerformExtendedEuclidean(element, prime)
            if vals[1] < 0:
                inverse = prime + vals[1]
            else:
                inverse = vals[1]
            return inverse
        except Exception as ex:
            print("An error occurred in function Decryption.GetInverseModPrime while processing. Error: ", ex)