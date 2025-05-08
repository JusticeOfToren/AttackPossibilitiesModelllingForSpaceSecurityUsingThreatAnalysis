#!/usr/bin/env python3
"""
Module Name: tatfloader_tests.py
Description: Tests tatfloader
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import tatfloader

mitre_tactics_array=["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection","command-and-control","exfiltration","impact"]
class Tests(unittest.TestCase):
    def test_load_dataset(self):
        technique_array, threat_actor_names_array = tatfloader.load_dataset()
        i=0
        for actor in threat_actor_names_array:
            if actor[0] == "Indrik Spider": # Non aerospace
                indrik_spider_index = i
                actual_indrik_spider_aerospace = actor[1]
            if actor[0] == "Kimsuky": # Non aerospace
                kimsuky_index = i
            if actor[0] == "menuPass": # Aerospace
                menupass_index = i
                actual_menupass_aerospace = actor[1]
                actual_menupass_percentage = actor[2]
            if actor[0] == "Molerats": # Aerospace
                molerats_index = i
            if actor[0] == "Aeroblade": # Aerospace Not In Mitre
                aeroblade_index = i
            if actor[0] == "APT41": # Non aerospace
                apt41_index = i
            if actor[0] == "Avivore": # Aerospace Not in Mitre
                actual_avivore_aerospace = actor[1]
                actual_avivore_percentage = actor[2]
            i+=1
        expected_indrik_spider_execution=[1059.001, 1059.003, 1047.0, 1059.007, 1204.002]
        actual_indrik_spider_execution=technique_array[indrik_spider_index][3]
        expected_kimsuky_resource_development=[1587.001, 1585.002, 1588.002, 1608.001, 1587.0, 1583.004, 1583.001, 1585.001, 1586.002, 1584.001, 1588.005, 1583.006]
        actual_kimsuky_resource_development=technique_array[kimsuky_index][1]
        expected_menupass_credential_access=[1003.003, 1003.002, 1003.004, 1056.0]
        actual_menupass_credential_access=technique_array[menupass_index][7]
        expected_molerats_persistance=[1547.001, 1053.0, 1060.0, 1023.0]
        actual_molerats_persistance=technique_array[molerats_index][4]
        expected_aeroblade_c2=[1071.001, 1001.0, 1573.001, 1105.0]
        actual_aeroblade_c2=technique_array[aeroblade_index][11]
        expected_apt41_impact=[1496.0, 1486.0]
        actual_apt41_impact=technique_array[apt41_index][13]
        self.assertEqual(actual_indrik_spider_execution, expected_indrik_spider_execution,'Incorrect techniques for Indrik Spider')
        self.assertEqual(actual_indrik_spider_aerospace, False,'Incorrect aerospace designation for Indrik Spider')
        self.assertEqual(actual_kimsuky_resource_development, expected_kimsuky_resource_development,'Incorrect techniques for Kimsuky')
        self.assertEqual(actual_menupass_credential_access, expected_menupass_credential_access,'Incorrect techniques for menuPass')
        self.assertEqual(actual_menupass_aerospace, True,'Incorrect aerospace designation for menuPass')
        self.assertEqual(actual_menupass_percentage, 0.5,'Incorrect space attack percentage for menuPass')
        self.assertEqual(actual_avivore_aerospace, True,'Incorrect aerospace designation for Avivore')
        self.assertEqual(actual_avivore_percentage, 1,'Incorrect space attack percentage for Avivore')
        self.assertEqual(actual_molerats_persistance, expected_molerats_persistance,'Incorrect techniques for Molerats')
        self.assertEqual(actual_aeroblade_c2, expected_aeroblade_c2,'Incorrect techniques for Aeroblade')
        self.assertEqual(actual_apt41_impact, expected_apt41_impact,'Incorrect techniques for APT41')

        return
if __name__ == '__main__':
    unittest.main()