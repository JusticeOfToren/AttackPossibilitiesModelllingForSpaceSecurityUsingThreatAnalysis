#!/usr/bin/env python3
"""
Module Name: top10_tests.py
Description: Tests top10
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import ATTandCKProbablisticModel.top10
from stix2 import Filter, FileSystemSource
import math
import tatfloader
src = FileSystemSource('./cti-master/enterprise-attack') # The ATT&CK CTI enterprise dataset, used to get the tactic for each technique
techniques_to_tactics_array = []
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[1003],[1083],[1570],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[1003],[1083],[1570],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[1003],[1083],[],[1119],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[1003],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[1068],[],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[1574.002],[],[],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[1072],[],[],[],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[1583],[],[],[],[],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[1583.001],[],[],[],[],[],[],[],[],[],[],[],[]])
techniques_to_tactics_array.append([[1589],[],[],[],[],[],[],[],[],[],[],[],[],[]])
threat_actor_names_array=[["Imperial Kitten", True,0.5],["Aeroblade", True,0.5],["Anchor Panda", True,0.5],["APT3", True,0.75],["Turbine Panda", True,1],["Turla",True,1],["Tester",True, 0.75],["Test2",True,1],["Test3",True,0.5],["Test4",True,0.75],["Test5",True,1]]
tactics_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]
class Tests(unittest.TestCase):
    def test_get_occurance_dictionary(self):
        occurdictexpected={1589:11,1583.001:10,1583:9,1072:8,1574.002:7,1068:6,1036:5,1003:4,1083:3,1570:2,1119:1}
        techniques=[1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1570,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1570,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1119,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,
                    1589,1583.001,1583,1072,1574.002,1068,1036,
                    1589,1583.001,1583,1072,1574.002,1068,
                    1589,1583.001,1583,1072,1574.002,
                    1589,1583.001,1583,1072,
                    1589,1583.001,1583,
                    1589,1583.001,
                    1589]
        occurdictactual,techniquesactual = ATTandCKProbablisticModel.top10.get_occurance_dictionary(techniques_to_tactics_array,threat_actor_names_array)
        self.assertEqual([occurdictactual,techniquesactual], [occurdictexpected,techniques], 'Incorrect Return')
    def test_get_occurance_dictionary_mixed_aerospace(self):
        altered_threat_actor_names_array=[["Imperial Kitten", False,0],["Aeroblade", True,0.5],["Anchor Panda", True,0.5],["APT3", True,0.75],["Turbine Panda", True,1],["Turla",True,1],["Tester",True, 0.75],["Test2",True,1],["Test3",True,0.5],["Test4",True,0.75],["Test5",True,1]]
        occurdictexpected={1589:11,1583.001:10,1583:9,1072:8,1574.002:7,1068:6,1036:5,1003:4,1083:3,1570:2,1119:1}
        techniques=[1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1570,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1570,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1119,
                    1589,1583.001,1583,1072,1574.002,1068,1036,1003,
                    1589,1583.001,1583,1072,1574.002,1068,1036,
                    1589,1583.001,1583,1072,1574.002,1068,
                    1589,1583.001,1583,1072,1574.002,
                    1589,1583.001,1583,1072,
                    1589,1583.001,1583,
                    1589,1583.001,
                    1589]
        occurdictactual,techniquesactual = ATTandCKProbablisticModel.top10.get_occurance_dictionary(techniques_to_tactics_array,altered_threat_actor_names_array)
        self.assertNotEqual([occurdictactual,techniquesactual], [occurdictexpected,techniques], 'Incorrect Return')
    def test_key_with_max_value(self):
        testdict={1589:10,1583.001:9,1583:8,1072:7,1574.002:6,1068:5,1036:4,1003:3,1083:2,1570:1,1119:1}
        self.assertEqual(ATTandCKProbablisticModel.top10.keywithmaxval(testdict),1589,'Wrong max value from dictionary')
        testdict2={1589:9,1583.001:9,1583:8,1072:7,1574.002:6,1068:5,1036:4,1003:3,1083:2,1570:1,1119:1}
        self.assertEqual(ATTandCKProbablisticModel.top10.keywithmaxval(testdict2),1589,'Wrong max value from dictionary when two max values exist')

    def test_get_top_10_techniques(self):
        top10expected=[1589,1583.001,1583,1072,1574.002,1068,1036,1003,1083,1570]
        self.assertEqual(ATTandCKProbablisticModel.top10.get_top_10_techniques(techniques_to_tactics_array,threat_actor_names_array),top10expected,'Incorrect top 10 list')

    def test_get_occurances_without_subtechniques(self):
        occurdictexpected={1589:11,1583:19,1072:8,1574:7,1068:6,1036:5,1003:4,1083:3,1570:2,1119:1}
        occurdictactual = ATTandCKProbablisticModel.top10.get_occurances_without_subtechniques(techniques_to_tactics_array,threat_actor_names_array)
        self.assertEqual(occurdictactual, occurdictexpected, 'Incorrect Return')
    
    def test_get_occurances_without_subtechniques_mixed_aerospace(self):
        altered_threat_actor_names_array=[["Imperial Kitten", False,0],["Aeroblade", True,0.5],["Anchor Panda", True,0.5],["APT3", True,0.75],["Turbine Panda", True,1],["Turla",True,1],["Tester",True, 0.75],["Test2",True,1],["Test3",True,0.5],["Test4",True,0.75],["Test5",True,1]]
        occurdictexpected={1589:11,1583:19,1072:8,1574:7,1068:6,1036:5,1003:4,1083:3,1570:2,1119:1}
        occurdictactual = ATTandCKProbablisticModel.top10.get_occurances_without_subtechniques(techniques_to_tactics_array,altered_threat_actor_names_array)
        self.assertNotEqual(occurdictactual, occurdictexpected, 'Incorrect Return for get_occurances_without_subtechniques with mixed aerospace attackers')
    
    def test_get_top_10_techniques_without_subtechniques(self):
        top10expected=[1583,1589,1072,1574,1068,1036,1003,1083,1570,1119]
        self.assertEqual(ATTandCKProbablisticModel.top10.get_top_10_techniques_without_subtechniques(techniques_to_tactics_array,threat_actor_names_array),top10expected,'Incorrect top 10 list')
if __name__ == '__main__':
    unittest.main()