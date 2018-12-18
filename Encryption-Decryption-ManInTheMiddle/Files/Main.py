# -*- coding: utf-8 -*-
"""
Created on Sun Nov 18 15:14:04 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       This is the starting point for the entire project

from Common import Common
from Encryption import Encryption
from KeyGeneration import KeyGeneration
from Decryption import Decryption
from BreakEncryption import BreakEncryption

class Main:
    #Constructor for Main class
    def __init__(self):
        try:
            self.__usrInpt = -1
            self.common = Common("KEY.txt", "ENC.txt")
            self.keyGeneration = KeyGeneration(self.common)
            self.encryption = Encryption(self.common)
            self.decryption = Decryption(self.common)
            self.breakEncryption = BreakEncryption(self.common)
        except Exception as ex:
            print("An error occurred while initializing class Main. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "usrInpt: " + str(self.__usrInpt) + ", keyGeneration: " + str(self.keyGeneration) + ", common: " + str(self.common) + \
    ", encryption: " + str(self.encryption) + ", decryption: " + str(self.decryption) + ", breakEncryption: " + str(self.breakEncryption)
    
    #User interface
    def Start(self):
        try:
            while self.__usrInpt != 0:
                print("\nMain Menu:\n",\
                      "\n1. Generate Keys (Elgamal Algorithm)",\
                      "\n2. Encrypt Message (Requires Reciever's Public Key)",\
                      "\n3. Decrypt Message (Requires Receiver's Private Key)",\
                      "\n4. Break Encryption & Decipher Message (Baby Step Giant Step Algorithm)",\
                      "\n0. Exit",\
                      "\nPlease enter a digit corresponding to the step")
                userEntered = input("(e.g. 1/2/../0): ")
                result = self.common.IsInteger(userEntered)
                
                if result is False:
                    self.__usrInpt = -1
                else:
                    self.__usrInpt = result
                
                if self.__usrInpt == 1:
                    self.keyGeneration.GenerateAndStoreKeys()
                elif self.__usrInpt == 2:
                    self.encryption.EncryptMessage();
                elif self.__usrInpt == 3:
                    self.decryption.DecryptMessage();
                elif self.__usrInpt == 4:
                    self.breakEncryption.BreakEncryptionGetMessage();
                elif self.__usrInpt == 0:
                    print("\nExiting...")
                else:
                    print("\nInvalid Input entered! Please retry.")
        except Exception as ex:
            print("An error occurred in function Main.Start while processing. Error: ", ex)
        finally:
            print("\nThank you!", \
                  "\nPython project on Encryption, Decryption and Man-In-The-Middle attack implementation", \
                  "\nsubmitted by Aayush Garg aayushgarg.bu@gmail.com")

###############################################################################

main = Main()
main.Start()