#!/usr/bin/env python3
"""
Module Name: top10.py
Description: Outputs the top 10 mitre techniques in aerospace
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import math
# https://stackoverflow.com/questions/714063/importing-modules-from-parent-folder
import os
import sys
import inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 
import tatfloader
'''https://stackoverflow.com/a/12343826'''
def keywithmaxval(d):
     """ a) create a list of the dict's keys and values; 
         b) return the key with the max value"""  
     v = list(d.values())
     k = list(d.keys())
     return k[v.index(max(v))]


def get_occurance_dictionary(techniques,threatactors):
    occurdict={}
    listoftechniques=[]
    for i, techniquelists in enumerate(techniques):
        if threatactors[i][1]:  # If current threat actor is active in aerospace
            for techniquelist in techniquelists: # Merges the multiple technique lists per attacker into one technique list for all attackers
                for technique in techniquelist:
                    listoftechniques.append(technique)
    for technique in listoftechniques:
        if technique not in occurdict.keys(): # If the technique isn't in the occurdict, add it and count its occurances
            x = listoftechniques.count(technique)
            occurdict[technique] = x
    return occurdict,listoftechniques # List of techniques returned for unit testing


def get_top_10_techniques(techniques,threatactors):
    top10=[]
    occurdict,listoftechniques = get_occurance_dictionary(techniques,threatactors)
    print("-------------Top 10 Techniques in Aerospace--------------")
    for i in range(10):
        if(len(occurdict) > 0):
            topxtechnique=keywithmaxval(occurdict) # Retrieves the technique with the highest number of occurances
        else:
            print("All techniques expended")
            break
        occurances=occurdict[topxtechnique]
        if int(topxtechnique)==topxtechnique: # If the technique is an integer i.e for our purposes, is not a subtechnique
            topxtechniqueprint=int(topxtechnique)
        else:
            topxtechniqueprint=topxtechnique
        print("{}. T{} with {} occurrences".format(i+1,topxtechniqueprint, occurances))
        top10.append(topxtechnique)
        occurdict.pop(topxtechnique)
        while True: # Until a technique has a different number of occurances than the above one
            if(len(occurdict) > 0):
                topxtechnique=keywithmaxval(occurdict) # Retrieves the technique with the highest number of occurances
            else:
                print("All techniques expended")
                break
            if int(topxtechnique)==topxtechnique:
                topxtechniqueprint=int(topxtechnique)
            else:
                topxtechniqueprint=topxtechnique
            if occurdict[topxtechnique] == occurances: # If a technique has a different number of occurances than the above one
                print("{}. T{} with {} occurrences".format(i+1,topxtechniqueprint, occurances))
                top10.append(topxtechnique)
                occurdict.pop(topxtechnique)
            else:
                break # Move to the next iteration of i
    print("------------------------------------------------------------------")
    return top10 # Used for unit testing


def get_occurances_without_subtechniques(techniques,threatactors):
    occurdict,listoftechniques = get_occurance_dictionary(techniques,threatactors)
    '''Techniques without subtechniques'''
    usedlist=[]
    occurdictnosub={}
    
    for technique in listoftechniques:
        if technique not in usedlist:
            usedlist.append(technique)
            trunctech=math.trunc(technique) # Gets the supertechnique from a subtechnique
            x = listoftechniques.count(technique) 
            if trunctech not in occurdictnosub.keys(): # If the current technique(or supertechnique if the current is a subtechnique) hasn't been counted
                occurdictnosub[trunctech] = x
            else:
                occurdictnosub[trunctech] = occurdictnosub[trunctech] + x
    return occurdictnosub

def get_top_10_techniques_without_subtechniques(techniques,threatactors):
    top10nosub=[]
    occurdictnosub = get_occurances_without_subtechniques(techniques,threatactors)
    print("-------------Top 10 Techniques in Aerospace without Subtechniques--------------")
    for i in range(10):
        if(len(occurdictnosub) > 0):
            topxtechnique=keywithmaxval(occurdictnosub) # Retrieves the technique with the highest number of occurances
        else:
            print("All techniques expended")
            break
        occurances=occurdictnosub[topxtechnique]
        if int(topxtechnique)==topxtechnique:
            topxtechniqueprint=int(topxtechnique)
        else:
            topxtechniqueprint=topxtechnique
        print("{}. T{} with {} occurrences".format(i+1,topxtechniqueprint, occurances))
        top10nosub.append(topxtechnique)
        occurdictnosub.pop(topxtechnique)
        while True:
            if(len(occurdictnosub) > 0):
                topxtechnique=keywithmaxval(occurdictnosub) # Retrieves the technique with the highest number of occurances
            else:
                print("All techniques expended")
                break
            if int(topxtechnique)==topxtechnique:
                topxtechniqueprint=int(topxtechnique)
            else:
                topxtechniqueprint=topxtechnique
            if occurdictnosub[topxtechnique] == occurances:
                print("{}. T{} with {} occurrences".format(i+1,topxtechniqueprint, occurances))
                top10nosub.append(topxtechnique)
                occurdictnosub.pop(topxtechnique)
            else:
                break
    return top10nosub # Used for unit testing

if __name__ == '__main__':
    technique_array, threat_actor_names_array = tatfloader.load_dataset()
    get_top_10_techniques(technique_array,threat_actor_names_array)
    get_top_10_techniques_without_subtechniques(technique_array,threat_actor_names_array)