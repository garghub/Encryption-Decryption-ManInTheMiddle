# -*- coding: utf-8 -*-
"""
Created on Mon Nov 26 21:05:14 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       Main.py is the starting point for the entire project

import math
from Encryption import Encryption
from KeyGeneration import KeyGeneration
from Decryption import Decryption


class BreakEncryption:
    #Constructor for BreakEncryption class
    def __init__(self, objCommon):
        try:
            self.common = objCommon
            self.encryption = Encryption(objCommon)
            self.keyGeneration = KeyGeneration(objCommon)
            self.decryption = Decryption(objCommon)
        except Exception as ex:
            print("An error occurred while initializing class BreakEncryption. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "No member variables other than member objects to classes"
    
    #4. Break encryption and get original message using Baby Step Giant Step algorithm
    def BreakEncryptionGetMessage(self):
        try:
            print("\nIf your listening to somebody's conversation as a Man In The Middle",\
                  "and wish to break an encrypted message,")
            print("you must have the knowledge of encrypted message and the header sent to the Reciever.")
            
            #Read Encrypted Message and Header from the file
            tupleEncMsgHead = self.encryption.ReadEncryptedMessageAndHeader()
            
            if len(tupleEncMsgHead) > 0:
                print("\nThe public key of the Receiver is required to break an encryption.")
                print("The Public Keys are usually publicly available via Key Hosting Services.")
        
                #Read public key from file
                receiversKeys = self.keyGeneration.ReadReceiversKeys(False)
                
                if len(receiversKeys) > 0:            
                    encryptedMessage, header = tupleEncMsgHead[0], tupleEncMsgHead[1]
                    primitiveElement = receiversKeys[0]
                    primitiveRaisedSecretModPrime = receiversKeys[1]
                    randomPrime = receiversKeys[2]
                    
                    print("\nBreaking Encyption (using Baby Step Giant Step Algorithm)...")
                    self.__PerformBabyStepGiantStep(
                            encryptedMessage, header, primitiveElement, primitiveRaisedSecretModPrime, randomPrime)
                    
        except Exception as ex:
            print("An error occurred in function BreakEncryption.BreakEncryptionGetMessage while processing. Error: ", ex)
    
    #To perform Baby-Step-Giant-Step algorithm using Receiver's public keys and Header to break Encryption
    #   and get the original message
    def __PerformBabyStepGiantStep(self, encryptedMessage, header, primitiveElement, primitiveRaisedSecretModPrime, randomPrime):
        try:
            randomVar = self.__ComputePowerVariable(header, primitiveElement, randomPrime)
            #print("randomVar:", randomVar)
            if randomVar == -1:
                print("\nBaby Step Giant Step failed to break encryption for given Public Key and Header combination.")
                print("Please try again for a different Receiever\'s Public Key and Header combination...")
            else:
                #Encrypted Message = message * (c^b mod p) mod p
                #message = Encrypted Message * Inverse of (c^b mod p) mod p
                
                #c^b mod p
                primitiveRaisedSecRaisedRandomModPrime = self.common.GetExponentiation(primitiveRaisedSecretModPrime
                                                                           , randomVar, randomPrime)
                #print("primitiveRaisedSecRaisedRandomModPrime:", primitiveRaisedSecRaisedRandomModPrime)
                #message = Encrypted Message * Inverse of (c^b mod p) mod p
                message = (encryptedMessage * self.decryption.GetInverseModPrime(primitiveRaisedSecRaisedRandomModPrime, randomPrime)) % randomPrime
                print("\nCracked Original Message:", message)
                
        except Exception as ex:
            print("An error occurred in function BreakEncryption.__PerformBabyStepGiantStep while processing. Error: ", ex)
    
    #In the equation a = b ^ c mod n, below function computes 'c'
    # Representationally: answerVar = baseVar ^ powerVar Mod prime
    def __ComputePowerVariable(self, answerVar, baseVar, prime):
        try:
            dictLHS, dictRHS = {}, {}
            m = int(math.ceil(math.sqrt(prime - 1)))
            #print("m:", m)
            invBaseVar = self.decryption.GetInverseModPrime (baseVar, prime)
            #print("invBaseVar:", invBaseVar)
            invBaseVarRaisedm = self.common.GetExponentiation(invBaseVar, m, prime)
            #print("invBaseVarRaisedm:", invBaseVarRaisedm)
            
            #answerVar * (invBaseVar ^ m) ^ i  =  baseVar ^ j
            #where 0 <= i <=m
            #and 0 <= j < m
                
            #All L.H.S. values of equation answerVar * (invBaseVar ^ m) ^ i  =  baseVar ^ j
            for i in range(m + 1):
                valueLHS = (self.common.GetExponentiation(invBaseVarRaisedm, i, prime) * answerVar) % prime
                dictLHS[i] = valueLHS
            
            #All R.H.S. values of equation answerVar * (invBaseVar ^ m) ^ powerVar  =  baseVar ^ otherPowerVar
            for j in range(m):
                valueRHS = self.common.GetExponentiation(baseVar, j, prime)
                dictRHS[j] = valueRHS
            
            listCombinationTuple = [(i,j) for i in dictLHS for j in dictRHS if dictLHS[i] == dictRHS[j]]
            #print("listCombinationTuple:", listCombinationTuple)
            if len(listCombinationTuple) > 0:
                powerVar = int((listCombinationTuple[0][0] * m) + listCombinationTuple[0][1])
            else:
                #Baby-Step-Giant-Step algorithm failed to crack encryption
                powerVar = -1
            #print("powerVar:", powerVar)
            return powerVar
        except Exception as ex:
            print("An error occurred in function BreakEncryption.__ComputePowerVariable while processing. Error: ", ex)