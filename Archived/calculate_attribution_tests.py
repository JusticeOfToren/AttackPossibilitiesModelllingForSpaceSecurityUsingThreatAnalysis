#!/usr/bin/env python3
"""
Module Name: calculate_attribution_tests.py
Description: Tests calculate_attribution
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""
import unittest
import ATTandCKProbablisticModel.calculateattribution
from stix2 import Filter, FileSystemSource
import math
import tatfloader
src = FileSystemSource('./cti-master/enterprise-attack') # The ATT&CK CTI enterprise dataset, used to get the tactic for each technique
technique_array, threat_actor_names_array = tatfloader.load_dataset()
tactics_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]
class Tests(unittest.TestCase):
    def test_get_index_of_array(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_index_of_array('resource-development'), 1, 'Wrong Index Returned')
    def test_get_tactic_by_technique(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_tactic_by_technique(src,'T1071'), 11, 'Wrong Index Returned')
    def test_get_actors_using_technique(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_actors_using_technique(src,'T1489'),[3,4,91,129,137,142],'Wrong number of matches')
    def test_get_actors_using_subtechnique(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_actors_using_technique(src,'T1595.002'),[17,18,34,36,63,91,112,117,130,155,172],'Wrong number of matches')
    def test_generate_sub_techniques(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.generate_sub_techniques('1000.0'),[1000.0,1000.001,1000.002,1000.003,1000.004,1000.005,1000.006,1000.007,1000.008,1000.009,1000.01,1000.011,1000.012,1000.013,1000.014,1000.015,1000.016,1000.017],'Incorrect generation')
    def test_get_num_technique_matches_per_actor(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[91]=1
        num_technique_matches[3]=1
        num_technique_matches[4]=1
        num_technique_matches[129]=1
        num_technique_matches[17]=1
        num_technique_matches[18]=1
        num_technique_matches[34]=1
        num_technique_matches[36]=1
        num_technique_matches[63]=1
        num_technique_matches[91]+=1
        num_technique_matches[112]=1
        num_technique_matches[117]=1
        num_technique_matches[130]=1
        num_technique_matches[137]=1
        num_technique_matches[142]=1
        num_technique_matches[155]=1
        num_technique_matches[172]=1
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_num_technique_matches_per_actor(src,['T1489','T1595.002']),num_technique_matches,'Wrong number of matches')
    def test_get_num_actors_greater_than_zero(self):
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.get_num_actors_greater_than_zero([2,4,0,7,8]),4,'Wrong number of matches')
    def test_chance_of_space_attack(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=1 # aerospace max
        num_technique_matches[34]=7 # non aerospace
        num_technique_matches[38]=3 # aerospace likely
        block_prob=0.8
        self.assertEqual(round(ATTandCKProbablisticModel.calculateattribution.chance_of_space_attack(num_technique_matches, block_prob),2),2.60,'Wrong value')
    def test_ranked_block_calculator(self):
        non_space = 1*3 + 0.5*2 + 0.5*2
        space = 0.25*2
        rank_matches =  {0:[13],1:[2,7],2:[21,23,24],3:[6],4:[]}
        space_actual,non_space_actual, top_rank_actual = ATTandCKProbablisticModel.calculateattribution.ranked_block_calculator(4,rank_matches)
        actual_output = [space_actual,non_space_actual, top_rank_actual]
        self.assertEqual(actual_output,[space, non_space,[6]],'Block count incorrect')
    def test_ranked_matches(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=1
        num_technique_matches[34]=7
        num_technique_matches[38]=3
        num_technique_matches[100]=7
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.ranked_matches(8,num_technique_matches),[34,100],'Top rank incorrect')
    def test_highest_block_calculator(self):
        non_space = 0
        space = 1.75
        highest_rank = [2,38]
        space_actual,non_space_actual, attackernames = ATTandCKProbablisticModel.calculateattribution.highest_matches_block_calculator(highest_rank)
        actual_output = [space_actual,non_space_actual, attackernames]
        self.assertEqual(actual_output,[space, non_space,['APT38','APT18']],'Highest block count incorrect')
    def test_highest_matches(self):
        highest_rank = [2,38]
        self.assertEqual(ATTandCKProbablisticModel.calculateattribution.highest_matches(highest_rank),['APT38','APT18'],'Highest Blocks Output Incorrect')
    def test_calculate_alternate_block_calculator(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=7
        num_technique_matches[38]=6
        num_technique_matches[17]=3
        num_technique_matches[18]=4
        num_technique_matches[34]=2
        num_technique_matches[36]=5
        num_technique_matches[63]=1
        num_technique_matches[112]=1
        num_technique_matches[117]=1
        num_technique_matches[130]=1
        num_technique_matches[155]=1
        num_technique_matches[172]=1
        space_attack_chance, non_space_chance = ATTandCKProbablisticModel.calculateattribution.calculate_alternate_block_calculator(num_technique_matches, 11)
        actual_output = [space_attack_chance, non_space_chance]
        expected_output = [7+6*0.75, 0]
        self.assertEqual(actual_output,expected_output,'Incorrect blocks calculation')
    # Negative Tests
    def test_get_index_of_array_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_index_of_array('impact'), 1, 'Wrong Index Returned')
    def test_get_tactic_by_technique_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_tactic_by_technique(src,'T1651'), 11, 'Wrong Index Returned')
    def test_get_actors_using_technique_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_actors_using_technique(src,'T1651'),[91,129],'Wrong number of matches')
    def test_get_actors_using_subtechnique_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_actors_using_technique(src,'T1651'),[17,18,34,36,63,91,112,117,130,155,172],'Wrong number of matches')
    def test_generate_sub_techniques_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.generate_sub_techniques('1001.0'),[1000.0,1000.001,1000.002,1000.003,1000.004,1000.005,1000.006,1000.007,1000.008,1000.009,1000.01,1000.011,1000.012,1000.013,1000.014,1000.015,1000.016,1000.017],'Incorrect generation')
    def test_get_num_technique_matches_per_actor_negative(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[91]=1
        num_technique_matches[129]=1
        num_technique_matches[17]=1
        num_technique_matches[18]=1
        num_technique_matches[34]=1
        num_technique_matches[36]=1
        num_technique_matches[63]=1
        num_technique_matches[91]+=1
        num_technique_matches[112]=1
        num_technique_matches[117]=1
        num_technique_matches[130]=1
        num_technique_matches[155]=1
        num_technique_matches[172]=1
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_num_technique_matches_per_actor(src,['T1651','T1595.002']),num_technique_matches,'Wrong number of matches')
    def test_get_num_actors_greater_than_zero_negative(self):
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.get_num_actors_greater_than_zero([2,0,0,7,8]),4,'Wrong number of matches')
    def test_chance_of_space_attack_negative(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=1
        num_technique_matches[34]=4
        num_technique_matches[38]=1
        block_prob=0.8
        self.assertNotEqual(round(ATTandCKProbablisticModel.calculateattribution.chance_of_space_attack(num_technique_matches, block_prob),2),2.60,'Wrong value')
    def test_ranked_block_calculator_negative(self):
        non_space = 1 + 0.5 + 0.5
        space = 0.25
        rank_matches =  {0:[13],1:[2,7],2:[21,23],3:[6],4:[]}
        space_actual,non_space_actual, top_rank_actual = ATTandCKProbablisticModel.calculateattribution.ranked_block_calculator(4,rank_matches)
        actual_output = [space_actual,non_space_actual, top_rank_actual]
        self.assertNotEqual(actual_output,[space, non_space,[5]],'Block count incorrect')
    def test_ranked_matches_negative(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=1
        num_technique_matches[34]=7
        num_technique_matches[35]=3
        num_technique_matches[100]=6
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.ranked_matches(8,num_technique_matches),[33,99],'Top rank incorrect')
    def test_highest_block_calculator_negative(self):
        non_space = 0
        space = 1.75
        highest_rank = [2,36]
        space_actual,non_space_actual, attackernames = ATTandCKProbablisticModel.calculateattribution.highest_matches_block_calculator(highest_rank)
        actual_output = [space_actual,non_space_actual, attackernames]
        self.assertNotEqual(actual_output,[space, non_space,['APT38','APT18']],'Highest block count incorrect')
    def test_highest_matches_negative(self):
        highest_rank = [2,36]
        self.assertNotEqual(ATTandCKProbablisticModel.calculateattribution.highest_matches(highest_rank),['APT38','APT18'],'Highest Blocks Output Incorrect')
    def test_calculate_alternate_block_calculator_negative(self):
        num_technique_matches = [0]*(len(threat_actor_names_array))
        num_technique_matches[2]=7
        num_technique_matches[38]=0
        num_technique_matches[17]=3
        num_technique_matches[18]=4
        num_technique_matches[34]=2
        num_technique_matches[36]=5
        num_technique_matches[63]=1
        num_technique_matches[112]=1
        num_technique_matches[117]=1
        num_technique_matches[130]=1
        num_technique_matches[155]=1
        num_technique_matches[172]=1
        space_attack_chance, non_space_chance = ATTandCKProbablisticModel.calculateattribution.calculate_alternate_block_calculator(num_technique_matches, 11)
        actual_output = [space_attack_chance, non_space_chance]
        expected_output = [7+6*0.75, 0]
        self.assertNotEqual(actual_output,expected_output,'Incorrect blocks calculation')
if __name__ == '__main__':
    unittest.main()