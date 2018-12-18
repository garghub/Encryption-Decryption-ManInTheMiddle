# -*- coding: utf-8 -*-
"""
Created on Mon Nov 26 20:56:53 2018

@author: Aayush

Python Project on
Encryption, Decryption and Man-In-The-Middle attack implementation
submitted by Aayush Garg aayushgarg.bu@gmail.com
"""

#       Main.py is the starting point for the entire project

import random
import os.path

class Common:
    #Contructor for Common class
    def __init__(self, keyFileName, encFileName):
        try:
            self.__i = -1
            self.keyFile = keyFileName
            self.encFile = encFileName
        except Exception as ex:
            print("An error occurred while initializing class Common. Error: ", ex)
    
    #String Representation
    def __str__(self):
        return "i: " + str(self.__i) + ", keyFileName: " + str(self.keyFileName) + ", encFileName: " + str(self.encFileName)
    
    #To check if element is an integer
    def IsInteger(self, element):
        try:
            intgr = int(element)
            return intgr
        except Exception:
            return False
    
    #To check if an element is a dictionary
    def IsDictionary(self, element):
        try:
            dictElement = dict(eval(element))
            return dictElement
        except Exception:
            return False
    
    #To check 3 user entries
    def AreElementsIntegers(self, userEntry, count):
        try:
            splitEntries = userEntry.split(',')
            entries = []
            for entry in splitEntries:
                entries.append(int(entry))
            if len(entries) == count:
                return entries
            else:
                return False
        except Exception:
            return False
    
    #Store keys in file
    def WriteToFile(self, filename, content):
        try:
            print("\nWriting to file...")
            fileWritten = open(filename, "w")
            fileWritten.write(str(content))
            fileWritten.close()
            print("Successfully written.")
        except Exception as ex:
            print("An error occurred in function Common.WriteToFile while processing. Error: ", ex)
    
    #Generate a random prime number of provided upper limit
    def GetRandomPrime(self, limit):
        try:
            randomInt = random.randint(2, limit)
            while self.CheckPrime(randomInt) is False:
                randomInt = random.randint(1, limit)
            return randomInt
        except Exception as ex:
            print("An error occurred in function Common.GetRandomPrime while processing. Error: ", ex)
            
    #Check for prime characteristic
    def CheckPrime(self, randomInteger):
        try:
            incInt = 2
            while incInt <= round(randomInteger / 2):
                if randomInteger % incInt == 0:
                    return False
                incInt += 1
            return True
        except Exception as ex:
            print("An error occurred in function Common.CheckPrime while processing. Error: ", ex)
            
    #Get x ^ e mod y
    def GetExponentiation(self, x, e, y):
        try:
            #print((x ** e) % y)
            Y = 1
            while e > 0:
                if e % 2 == 0:
                    x = (x * x) % y
                    e = e / 2
                else:
                    e = e - 1
                    Y = (x * Y) % y
            return Y
        except Exception as ex:
            print("An error occurred in function Common.GetExponentiation while processing. Error: ", ex)
            
    #Finding file to read from
    def FindFile(self, filename):
        try:
            print("\nSearching File...")
            if os.path.isfile(filename):
                print("File found.")
                return True
            else:
                print("File not found in the directory!")
                return False
        except Exception as ex:
            print("An error occurred in function Common.FindFile while processing. Error: ", ex)
    
    #Read Keys from the file
    def ReadFromFile(self, filename):
        try:
            print("\nReading from file...")
            fileRead = open(filename, "r")
            fileContentRead = fileRead.read()
            print("Successfully read.")
            #print("File Content:", fileContentRead)
            fileRead.close()
            return str(fileContentRead)
        except Exception as ex:
            print("An error occurred in function Common.ReadFromFile while processing. Error: ", ex)