#!/usr/bin/env python3
"""
Module Name: tatfloader.py
Description: Build python data structures from datasets
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import pandas as pd
'''Checks if a given threat actor is in the mitre set'''
def is_in_mitre(source_name, threat_actor_names_array):
    try:
        x = threat_actor_names_array.index([source_name, False, 0])
    except ValueError:
        x = -1
    return x

'''Loads the Threat Actor Technique File spreadsheet into python data structures'''
def load_dataset():
    mitre_techniques = pd.read_excel('Datasets/ThreatActorTechniqueFile.xlsx',sheet_name='AttackTechniques')
    mitre_techniques = mitre_techniques.replace({float('nan'): None})
    no_rows = len(mitre_techniques)
    threat_actor_technique_array = [ [ [] for j in range(14) ] for j in range(no_rows) ]
    threat_actor_names_array = [["name", False, 0] for i in range (no_rows)]
    mitre_tactics_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]
    for col in mitre_techniques:
        if col == "Threat Actor Name":
            for i in range(0, no_rows):
                threat_actor_names_array[i] = [mitre_techniques[col][i], False, 0] # Instantiates threat actor as non aerospace with 0 chance of space attack
            continue
        if col == 'Threat Actor ID' or col == 'References': # Not necessary for this process
            continue
        for i in range(0, no_rows):
            current_index = mitre_tactics_array.index(col) # Retrieves the tactic index for the current column
            techniques_at_current_position = mitre_techniques[col][i]
            if techniques_at_current_position != None:
                techniques_list_at_current_position=techniques_at_current_position.split(", ") # Techniques are seperated by commas within a cell
                final_technqiues_list=[]
                for technique in techniques_list_at_current_position:
                    int_tech=float(technique.replace("T","")) # Removes the T and stores technique as float(subtechniques become floats to 3dp, techniques become floats to 1dp)
                    final_technqiues_list.append(int_tech)
            else:
                final_technqiues_list=[]
            threat_actor_technique_array[i][current_index] = final_technqiues_list

    # Repeat for non-mitre sources6
    non_mitre_techniques = pd.read_excel('Datasets/ThreatActorTechniqueFile.xlsx',sheet_name='AttackTechniquesNotInMitre')
    non_mitre_techniques = non_mitre_techniques.replace({float('nan'): None})
    non_mitre_to_mitre={}

    no_rows_non_mitre = len(non_mitre_techniques)
    for col in non_mitre_techniques:
        # Adding the nonmitre threat actors to the arrays and linking the indexes from the mitre dataset to those of the nonmitre dataset
        if col == "Threat Actor Name":
            for i in range(0, no_rows_non_mitre):
                mitre_index = is_in_mitre(non_mitre_techniques[col][i],threat_actor_names_array)
                if mitre_index == -1: # If threat actor is not in mitre dataset
                    threat_actor_names_array.append([non_mitre_techniques[col][i],False,0])
                    non_mitre_to_mitre[i]=len(threat_actor_names_array)-1 # Stores the position in the main array of each threat actor in the non mitre dataset
                    threat_actor_technique_array.append([[],[],[],[],[],[],[],[],[],[],[],[],[],[]])
                else:
                    non_mitre_to_mitre[i]=(mitre_index)
            continue
        if col == 'Threat Actor ID' or col == 'References' or col == 'Unnamed: 17':
            continue
        for i in range(0, no_rows_non_mitre):
            index_in_main_list=non_mitre_to_mitre[i]
            current_index = mitre_tactics_array.index(col)
            techniques_at_current_position = non_mitre_techniques[col][i]
            if techniques_at_current_position != None:
                techniques_list_at_current_position=techniques_at_current_position.split(", ")
                for technique in techniques_list_at_current_position:
                    int_tech=float(technique.replace("T",""))
                    if int_tech not in threat_actor_technique_array[index_in_main_list][current_index]:
                        threat_actor_technique_array[index_in_main_list][current_index].append(int_tech)
    targeted_space = pd.read_excel('Datasets/ThreatActorTechniqueFile.xlsx',sheet_name='Threat Actors')
    targeted_space = targeted_space.replace({float('nan'): None})
    length_space = len(targeted_space)
    for col in targeted_space:
        if col == "Targeted Space":
            for i in range(0, length_space):
                space_target_text = targeted_space[col][i]
                if space_target_text == "Yes":
                    space_target_bool = True
                    space_target_value = 1
                elif space_target_text == "Likely":
                    space_target_bool = True
                    space_target_value = 0.75
                else:
                    space_target_bool = True # Setting true for all aerospace to make it easier to pull aerospace data from the arrays
                    space_target_value = 0.5
                threat_actor_name=targeted_space["Threat Actor"][i]
                x = threat_actor_names_array.index([threat_actor_name,False, 0]) # All threat actors have this value as default
                threat_actor_names_array[x]=[threat_actor_name,space_target_bool,space_target_value]
    return threat_actor_technique_array, threat_actor_names_array