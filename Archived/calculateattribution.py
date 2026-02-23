#!/usr/bin/env python3
"""
Module Name: calculateattribution.py
Description: Determines the attribution for given attack strings
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

from stix2 import Filter, FileSystemSource
import math
# https://stackoverflow.com/questions/714063/importing-modules-from-parent-folder
import os
import sys
import inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 
import tatfloader
src = FileSystemSource('./cti-master/enterprise-attack') # The ATT&CK CTI enterprise dataset, used to get the tactic for each technique
technique_array, threat_actor_names_array = tatfloader.load_dataset()
tactics_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]

# https://github.com/mitre/cti

'''Retrieves the index of the tactic name from the tactics array'''
def get_index_of_array(tactic):
    return tactics_array.index(tactic)

'''Retrieves the tactic of a given technique'''
def get_tactic_by_technique(thesrc, techniquename):
    try:
        tactic = thesrc.query([ Filter("external_references.external_id", "=", techniquename), Filter("type", "=", "attack-pattern")])[0]["kill_chain_phases"][0]["phase_name"]
    except IndexError:
        print("No technique with the name: {} can be found within the CTI dataset. Please check your input for correctness and ensure your local copy of the CTI dataset in use is up-to-date".format(techniquename))
        return -1
    return get_index_of_array(tactic)

def generate_sub_techniques(technique):
    subtechniques = [float(technique)]
    base_sub = str(technique)
    for i in range(1, 18): # The highest number of subtechniques for a technique is 17
        if i < 10:
            current_subtechnique = base_sub + "0" + str(i)
        else:
            current_subtechnique = base_sub + str(i)
        subtechniques.append(float(current_subtechnique))
    return subtechniques

'''Returns an array of threat actors using a given technique'''
def get_actors_using_technique(thesrc, techniquename):
    tactic_index = get_tactic_by_technique(thesrc, techniquename) # The index of the tactic is needed to access the correct sub-array
    if tactic_index == -1:
        return -1
    technique_number = float(techniquename[1:]) # Removes the "T" from the start of the Technique ID
    tas_using_technique = []

    super_technique_number = math.trunc(float(technique_number)) # As the highest subtechnique is less than 50, treating the technique as a float and then truncating returns just the supertechnique 
    if super_technique_number == technique_number:
        subtechniques = generate_sub_techniques(technique_number) # Creates every subtechnique
    else:
        subtechniques = [technique_number]
    for i, threat_actor in enumerate(technique_array):
        threat_actor_techs_in_tactic = threat_actor[tactic_index]
        technique_intersection = set(subtechniques) & set(threat_actor_techs_in_tactic) # Checks whether any of the subtechniques are present
        if len(technique_intersection)>0: 
            tas_using_technique.append(i)
    return tas_using_technique

'''Counts the number of techniques from the attack string a given threat actor has used'''
def get_num_technique_matches_per_actor(thesrc, technique_list):
    num_technique_matches = [0]*(len(threat_actor_names_array))
    for technique in technique_list: # Iterates through the attack string
        actors_using_technique = get_actors_using_technique(thesrc, technique)
        if actors_using_technique == -1:
            continue
        for actor in actors_using_technique:
            num_technique_matches[actor]=num_technique_matches[actor]+1
    return num_technique_matches

'''Counts how many threat actors match at least one of the techniques in the attack string'''
def get_num_actors_greater_than_zero(num_matches):
    greater_zero = 0
    for i in num_matches:
        if i > 0:
            greater_zero+=1
    return greater_zero

'''The size of the attack string'''
def get_maximum_number_of_matches(attack_map):
    return len(attack_map)

'''Outputs probability for each threat actor'''
def output_probabilities(matches, block_prob, max_matches):
    for i,block in enumerate(matches):
        print("{0}: {1}%".format(threat_actor_names_array[i][0], round(block*block_prob, 2)))
        if block == max_matches: # If the threat actor matches every technique in the attack string
            print("   - Full Match")

'''Sums the probabilities from output_probabilities() where they are marked as an aerospace attacker'''
def chance_of_space_attack(matches, block_prob):
    space_attack_chance = 0
    for i,block in enumerate(matches):
        if threat_actor_names_array[i][1]: # If the current threat actor is an aerospace attacker
            space_attack_chance+=block*block_prob*threat_actor_names_array[i][2] # threat_actor_names_array[i][2] is the probability that the threat actor has attacked space
    return space_attack_chance

def ranked_block_calculator(max_matches, rank_matches):
    space_blocks = 0 # Number of matches among space attackers
    non_space_blocks = 0
    for i in range(0, max_matches):
        if rank_matches[max_matches-i] == []: # Cycles through from the highest number of matches until a rank with threat actors is found
            continue
        else:
            highest_rank = rank_matches[max_matches-i]
            for j in rank_matches[max_matches-i]:
                if threat_actor_names_array[j][1]: # If aerospace attacker
                    space_blocks+= (max_matches-i)*threat_actor_names_array[j][2]
                else:
                    non_space_blocks+=(max_matches-i)
            multiplier=0.5 # Decreases the amount a match is worth, in order to prioritise higher matches
            for k in range(max_matches-i-1,0,-1): # Decrements through remaining match numbers
                if k == 1 and max_matches > 3: # If there are enough techniques that matching one is not important
                    break
                for j in rank_matches[k]: # For 1 less than the highest number of matches, matches are counted for half, etc
                    if threat_actor_names_array[j][1]:
                        space_blocks+= k*threat_actor_names_array[j][2]*multiplier
                    else:
                        non_space_blocks+=k*multiplier
                multiplier=multiplier/4
            break
    return space_blocks, non_space_blocks, highest_rank
'''Sorts threat actors by how many matches they have with the attack string'''
def ranked_matches(max_matches, matches):
    rank_matches =  {}
    for i in range(0, max_matches):
        rank_matches[max_matches-i] = [] # Instantiates each rank
        for j,no_matches in enumerate(matches):
            if no_matches == max_matches-i: # If the current threat actor meets the current number of matches
                rank_matches[max_matches-i].append(j)
    
    space_blocks, non_space_blocks, highest_rank = ranked_block_calculator(max_matches, rank_matches)
    print("Space Blocks: {}".format(space_blocks))
    print("Non Space Blocks: {}".format(non_space_blocks))
    if non_space_blocks > 0:
        ratio = space_blocks/non_space_blocks
    else:
        if space_blocks > 0:
            ratio = 2 # The highest that the system cares about
        else:
            ratio = -1
    print("Ratio: {}".format(ratio))
    if ratio > 1:
        if ratio >= 2:
            print("Space Attack Highly Likely")
        elif ratio >= 1.5:
            print("Space Attack Likely")
        else:
            print("Space Attack Quite Likely")
    elif ratio == 1:
        print("Space Attack Likelihood Balanced(Equal chance Space Attacker or Non-Space Attacker)")
    elif ratio == -1:
        print("ERROR: No matches can be found for the given attack string in either aerospace attackers or general attacker")
    else:
        if ratio <= 0.5:
            print("Space Attack Very Unlikely")
        elif ratio <= 0.75:
            print("Space Attack Unlikely")
        else:
            print("Space Attack Quite Unlikely")
    print("--------------------------------------------")
        

    return highest_rank

def highest_matches_block_calculator(rank):
    space_chance = 0
    non_space_chance = 0
    attacker_names = []
    for i in rank:
        if threat_actor_names_array[i][1]:
            space_chance+=1*threat_actor_names_array[i][2]
            attacker_names.append(threat_actor_names_array[i][0])
        else:
            non_space_chance+=1
            attacker_names.append(threat_actor_names_array[i][0])
    return space_chance,non_space_chance,attacker_names

def highest_matches(rank):
    space_chance,non_space_chance,attacker_names = highest_matches_block_calculator(rank)
    if non_space_chance > 0:
        ratio=space_chance/non_space_chance
    else:
        if space_chance > 0:
            ratio = 2 # The highest that the system cares about
        else:
            ratio = -1 # If both are zero, no useful data is provided
    print("Space Blocks: {}".format(space_chance))
    print("Non Space Blocks: {}".format(non_space_chance))
    print("Ratio: {}".format(ratio))
    if ratio > 1:
        if ratio >= 2:
            print("Space Attack Highly Likely")
        elif ratio >= 1.5:
            print("Space Attack Likely")
        else:
            print("Space Attack Quite Likely")
    elif ratio == 1:
        print("Space Attack Likelihood Balanced(Equal chance Space Attacker or Non-Space Attacker)")
    elif ratio == -1:
        print("ERROR: No matches can be found for the given attack string in either aerospace attackers or general attacker")
    else:
        if ratio <= 0.5:
            print("Space Attack Very Unlikely")
        elif ratio <= 0.75:
            print("Space Attack Unlikely")
        else:
            print("Space Attack Quite Unlikely")
    return attacker_names


def calculate_alternate_block_calculator(matches, maxmatches):
    space_attack_chance = 0
    non_space_chance = 0
    for i,block in enumerate(matches):
        if threat_actor_names_array[i][1]:
            if block>=maxmatches/2: # If the current attacker matches at least 50% of the techniques
                space_attack_chance+=block*threat_actor_names_array[i][2]
        else:
            if block>=maxmatches/2:
                non_space_chance+=block
    return space_attack_chance, non_space_chance

'''Sums matches, but only for attackers who match at least half of the techniques in the attack string'''
def calculate_alternate(matches,maxmatches):
    space_attack_chance,non_space_chance = calculate_alternate_block_calculator(matches, maxmatches)
    print("Space Attack Blocks: {}".format(space_attack_chance))
    print("Non-space Attack Blocks: {}".format(non_space_chance))
    if non_space_chance > 0:
        ratio = space_attack_chance/non_space_chance
    else:
        if space_attack_chance > 0:
            ratio = 2 # The highest that the system cares about
        else:
            ratio = -1
    print("Ratio: {}".format(ratio))
    if ratio > 1:
        if ratio >= 2:
            print("Space Attack Highly Likely")
        elif ratio >= 1.5:
            print("Space Attack Likely")
        else:
            print("Space Attack Quite Likely")
    elif ratio == 1:
        print("Space Attack Likelihood Balanced(Equal chance Space Attacker or Non-Space Attacker)")
    elif ratio == -1:
        print("ERROR: No matches can be found for the given attack string in either aerospace attackers or general attacker")
    else:
        if ratio <= 0.5:
            print("Space Attack Very Unlikely")
        elif ratio <= 0.75:
            print("Space Attack Unlikely")
        else:
            print("Space Attack Quite Unlikely")
    print("--------------------------------------------")


'''Calls the other functions'''
def calculate_attribution(thesrc, attack_map):
    
    max_matches = get_maximum_number_of_matches(attack_map)
    num_matches = get_num_technique_matches_per_actor(thesrc, attack_map)
    num_actors_greater_than_zero = get_num_actors_greater_than_zero(num_matches)
    prob_per_block = 100/(max_matches*num_actors_greater_than_zero)
    print("------Probabilities for Calculation 1 ------------")
    output_probabilities(num_matches, prob_per_block, max_matches)
    space_threat = chance_of_space_attack(num_matches,prob_per_block)
    print("-------Calculation 1 - Equal Probabilities--------")
    print("Chance of Space Being Attacked: {0}%".format(round(space_threat, 2)))
    print("---------Calculation 2 - Blocks-------------------")
    calculate_alternate(num_matches,max_matches)
    print("---------Calculation 3 - Ranked Matches-----------")
    highest_rank = ranked_matches(max_matches,num_matches)
    print("-------Calculation 4 - Highest Matches------------")
    attacker_names = highest_matches(highest_rank)
    print("Attackers with highest number of matches")
    for name in attacker_names:
        print(name)
    print("---------------------------------------------")

'''Test Cases'''
# #CT-I1-1
# calculate_attribution(src,["T1598","T1053.003", "T1078.003","T1211","T1595","T1021","T1590.004","T1210","T1078.001","T1543"])
# CT-I2-1
# calculate_attribution(src,["T1592.001","T1566.001","T1595","T1210","T1592"])
# #CT-I3-1
# calculate_attribution(src,["T1589","T1586","T1189","T1070","T1534","T1546"])
# #CNE-I1-1
# calculate_attribution(src,["T1595","T1078.001","T1590","T1039","T1048"])

if __name__ == '__main__':
    attack_string = []
    attack_string_length = int(sys.argv[1])
    input_index = 2
    for i in range(attack_string_length):
        attack_string.append(sys.argv[input_index])
        input_index+=1
    calculate_attribution(src,attack_string)
    

