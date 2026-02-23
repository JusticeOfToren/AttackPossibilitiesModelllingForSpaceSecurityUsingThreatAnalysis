#!/usr/bin/env python3
"""
Module Name: techniquecomplexity.py
Description: Calculates the complexity of threat actors
Author: Benjamin McCullough
Date: Last Updated: 22/02/2026
Version: 1.1
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



'''Determining how many Space techniques there are'''
def no_techniques_in_space():
    occurdict={}
    listoftechniques=[]
    templatearray, templatearraynames = tatfloader.load_dataset()
    for i, techniquelists in enumerate(templatearray):
        if templatearraynames[i][1] and templatearraynames[i][2]>=0.75:  # If current threat actor has likely or certainly attacked Space
            current_attacker_techniques_list=[]
            for techniquelist in techniquelists:
                for technique in techniquelist:
                    if technique not in current_attacker_techniques_list: # If a technique shows up multiple times for an attacker
                        current_attacker_techniques_list.append(technique)
                        listoftechniques.append(technique)
    for technique in listoftechniques:
        if technique not in occurdict.keys():
            x = listoftechniques.count(technique)
            occurdict[technique] = x

    print("There are {} techniques used in the Space dataset".format(len(occurdict)))

src = FileSystemSource('./cti-master/enterprise-attack')
mitre_tactic_values=[0.25,0.7,0.5,0.75,0.9,0.8,0.9,0.8,0.4,0.9,0.6,0.6,0.6,0.7] # Values explained in the paper
mitre_types_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]

def calculate_complexity(technique_array=technique_array_default, threat_actor_name_array=threat_actor_name_array_default):
    complexities_space = 0
    no_complexities_space = 0
    complexities_other = 0
    no_complexities_other = 0
    frequencies_space = 0
    frequencies_other = 0
    no_space = 0
    no_other = 0
    for i, technique_lists in enumerate(technique_array):
        # Counts the number of Space and non-Space techniques
        if i==0:
            continue
        if threat_actor_name_array[i][1] and threat_actor_name_array[i][2]>=0.75: # If the attacker is likely or certain to have attacked space
            no_space += 1
        else:
            no_other += 1

        current_complexity_total = 0
        current_complexity_no = 0
        current_frequency = 0
        current_tactic=0
        current_attacker_techniques_dict = {}
        for technique_list in technique_lists:
            current_tactic_techniques = [] # The mitre dataset may contain multiples when an attacker and one of their associated campaigns both use a technique
            for technique in technique_list:
                if technique not in current_tactic_techniques:
                    if technique not in current_attacker_techniques_dict.keys():
                        tactic_value = mitre_tactic_values[current_tactic]
                        current_attacker_techniques_dict[technique]=[0,tactic_value,[tactic_value]] # [bool for multiple tactics, last tactic added, [all tactics so far]]
                        current_complexity_total += tactic_value # currentComplexityTotal and currentComplexityNo are used to calculate the mean average complexity
                        current_complexity_no += 1
                        if tactic_value > 0.7: # currentFrequency counts the number of high complexity techniques
                            current_frequency += 1
                    else:
                        technique_occurances = current_attacker_techniques_dict[technique][2]
                        technique_occurances.append(mitre_tactic_values[current_tactic])
                        if current_attacker_techniques_dict[technique][0] == 0:
                            complexity_to_remove = current_attacker_techniques_dict[technique][1]
                            current_complexity_total-=complexity_to_remove # Remove the existing complexity from the total
                            if complexity_to_remove > 0.7:
                                current_frequency-=1
                        current_attacker_techniques_dict[technique]=[1, mitre_tactic_values[current_tactic],technique_occurances]
                        
                    current_tactic_techniques.append(technique)
            current_tactic+=1
        for technique in current_attacker_techniques_dict:
            if current_attacker_techniques_dict[technique][0] == 1:
                calculated_tactic_value = round(sum(current_attacker_techniques_dict[technique][2])/len(current_attacker_techniques_dict[technique][2]), 1)
                current_complexity_total += calculated_tactic_value
                if calculated_tactic_value > 0.7: # currentFrequency counts the number of high complexity techniques
                    current_frequency += 1
        if current_complexity_no > 0: # Prevents divide by zero error
            current_average_complexity = current_complexity_total/current_complexity_no
            if threat_actor_name_array[i][1] and threat_actor_name_array[i][2]>=0.75:  # If current threat actor is active in Space
                complexities_space += current_average_complexity
                no_complexities_space += 1
                frequencies_space += current_frequency
            else:  # If current threat actor is not active in Space
                complexities_other += current_average_complexity
                no_complexities_other += 1
                frequencies_other += current_frequency


    average_frequency_space = frequencies_space/no_space
    average_frequency_other = frequencies_other/no_other
    average_complexity_space = complexities_space/no_space
    average_complexity_other = complexities_other/no_other
    return average_frequency_space,average_frequency_other, average_complexity_space, average_complexity_other



if __name__ == '__main__':
    average_frequency_space,average_frequency_other, average_complexity_space, average_complexity_other = calculate_complexity()
    print("---------------Space---------------------------")
    print("Average Complexity: {}".format(average_complexity_space))
    print("Average Frequency: {}".format(average_frequency_space))

    print("---------------Non-Space---------------------------")
    print("Average Complexity: {}".format(average_complexity_other))
    print("Average Frequency: {}".format(average_frequency_other))



