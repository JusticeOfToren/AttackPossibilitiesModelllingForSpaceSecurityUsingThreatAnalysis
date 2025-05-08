#!/usr/bin/env python3
"""
Module Name: techniquecomplexity.py
Description: Calculates the complexity of threat actors
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

# https://stackoverflow.com/questions/714063/importing-modules-from-parent-folder
import os
import sys
import inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 
import tatfloader
from stix2 import Filter, FileSystemSource
technique_array_default, threat_actor_name_array_default = tatfloader.load_dataset()



'''Determining how many aerospace techniques there are'''
def no_techniques_in_aerospace():
    occurdict={}
    listoftechniques=[]
    templatearray, templatearraynames = tatfloader.load_dataset()
    for i, techniquelists in enumerate(templatearray):
        if templatearraynames[i][1]:  # If current threat actor is active in aerospace
            for techniquelist in techniquelists:
                for technique in techniquelist:
                    listoftechniques.append(technique)
    for technique in listoftechniques:
        if technique not in occurdict.keys():
            x = listoftechniques.count(technique)
            occurdict[technique] = x

    print("There are {} techniques used in the aerospace dataset".format(len(occurdict)))

src = FileSystemSource('./cti-master/enterprise-attack')
mitre_tactic_values=[0.25,0.7,0.5,0.75,0.9,0.8,0.9,0.8,0.4,0.9,0.6,0.6,0.6,0.7] # Values explained in the paper
mitre_types_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]

def calculate_complexity(technique_array=technique_array_default, threat_actor_name_array=threat_actor_name_array_default):
    complexities_aerospace = 0
    no_complexities_aerospace = 0
    complexities_other = 0
    no_complexities_other = 0
    frequencies_aerospace = 0
    frequencies_other = 0
    no_aerospace = 0
    no_other = 0
    for i, technique_lists in enumerate(technique_array):
        # Counts the number of aerospace and non-aerospace techniques
        if i==0:
            continue
        if threat_actor_name_array[i][1]:
            no_aerospace += 1
        else:
            no_other += 1

        current_complexity_total = 0
        current_complexity_no = 0
        current_frequency = 0
        current_tactic=0
        for technique_list in technique_lists:
            for technique in technique_list:
                    tactic_value = mitre_tactic_values[current_tactic]
                    current_complexity_total += tactic_value # currentComplexityTotal and currentComplexityNo are used to calculate the mean average complexity
                    current_complexity_no += 1
                    if tactic_value > 0.7: # currentFrequency counts the number of high complexity techniques
                        current_frequency += 1
            current_tactic+=1
        if current_complexity_no > 0: # Prevents divide by zero error
            current_average_complexity = current_complexity_total/current_complexity_no
            if threat_actor_name_array[i][1]:  # If current threat actor is active in aerospace
                complexities_aerospace += current_average_complexity
                no_complexities_aerospace += 1
                frequencies_aerospace += current_frequency
            else:  # If current threat actor is not active in aerospace
                complexities_other += current_average_complexity
                no_complexities_other += 1
                frequencies_other += current_frequency


    average_frequency_aerospace = frequencies_aerospace/no_aerospace
    average_frequency_other = frequencies_other/no_other
    average_complexity_aerospace = complexities_aerospace/no_aerospace
    average_complexity_other = complexities_other/no_other
    return average_frequency_aerospace,average_frequency_other, average_complexity_aerospace, average_complexity_other



if __name__ == '__main__':
    average_frequency_aerospace,average_frequency_other, average_complexity_aerospace, average_complexity_other = calculate_complexity()
    print("---------------Aerospace---------------------------")
    print("Average Complexity: {}".format(average_complexity_aerospace))
    print("Average Frequency: {}".format(average_frequency_aerospace))

    print("---------------Non-Aerospace---------------------------")
    print("Average Complexity: {}".format(average_complexity_other))
    print("Average Frequency: {}".format(average_frequency_other))



