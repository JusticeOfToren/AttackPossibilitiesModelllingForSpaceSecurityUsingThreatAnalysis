#!/usr/bin/env python3
"""
Module Name:technique_complexity_tests.py
Description: Tests technique_complexity
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import ATTandCKProbablisticModel.techniquecomplexity
import os
here = os.path.dirname(os.path.abspath(__file__))

class Tests(unittest.TestCase):
    def test_calculate_complexity(self):
        mitre_tactic_values=[0.25,0.7,0.5,0.75,0.9,0.8,0.9,0.8,0.4,0.9,0.6,0.6,0.6,0.7]
        techniques_to_tactics_array = [[[],[],[],[],[],[],[],[],[],[],[],[],[],[]]]
        techniques_to_tactics_array.append([[],[],[1583],[1072],[1574.002],[],[1036],[1003],[1083],[1570],[],[],[],[]])
        techniques_to_tactics_array.append([[],[1583.001],[1583],[1072],[1574.002],[1068],[1036],[1003],[],[],[],[],[],[]])
        techniques_to_tactics_array.append([[1589],[1583.001],[1583],[],[],[1068],[1036],[],[1083],[],[1119],[],[],[]])
        techniques_to_tactics_array.append([[1589],[],[1583],[1072],[1574.002],[1068],[1036],[1003],[],[],[],[],[],[]])
        techniques_to_tactics_array.append([[1589],[],[1583],[],[1574.002],[],[1036],[],[],[],[],[],[],[]])
        #values in the program based on column rather than technique, makes difference in testing, where techniques may not be in correct column
        values={1583:0.5,1072:0.75,1574.002:0.9,1036:0.9,1003:0.8,1083:0.4,1570:0.9,1583.001:0.7,1068:0.8,1119:0.6,1589:0.25}
        threat_actor_names_array=[["None",False,0],["Imperial Kitten", False,0.5],["Aeroblade", True,0.5],["Anchor Panda", False,0.5],["APT3", True,0.75],["Turbine Panda", True,1]]
        expected_no_aerospace = 3
        expected_no_other = 2
        # Imperial Kitten
        complexity_imperial_kitten = values[1583] + values[1072] + values[1574.002] + values[1036] + values[1003] + values[1083] + values[1570]
        frequency_imperial_kitten = 0 + 1 + 1 + 1 + 1 + 0 + 1
        count_imperial_kitten = 7
        average_complexity_imperial_kitten = complexity_imperial_kitten/count_imperial_kitten
        complexity_aeroblade = values[1583.001] + values[1583] + values[1072] + values[1574.002] + values[1068] + values[1036] + values[1003]
        frequency_aeroblade = 0 + 0 + 1 + 1 + 1 + 1 + 1
        count_aeroblade = 7
        average_complexity_aeroblade = complexity_aeroblade/count_aeroblade
        complexity_anchor_panda = values[1589] + values[1583.001] + values[1583] + values[1068] + values[1036] + values[1083] + values[1119]
        frequency_anchor_panda = 0 + 0 + 0 + 1 + 1 + 0 + 0
        count_anchor_panda = 7
        average_complexity_anchor_panda = complexity_anchor_panda/count_anchor_panda
        complexity_apt3 = values[1589] + values[1583] + values[1072] + values[1574.002] + values[1068] + values[1036] + values[1003]
        frequency_apt3 = 0 + 0 + 1 + 1 + 1 + 1 + 1
        count_apt3 = 7
        average_complexity_apt3 = complexity_apt3/count_apt3
        complexity_turbine_panda = values[1589] + values[1583] + values[1574.002] + values[1036]
        frequency_turbine_panda = 0 + 0 + 1 + 1
        count_turbine_panda = 4
        average_complexity_turbine_panda = complexity_turbine_panda/count_turbine_panda

        expected_complexities_aerospace = (average_complexity_aeroblade + average_complexity_apt3 + average_complexity_turbine_panda)/expected_no_aerospace
        expected_complexities_other = (average_complexity_imperial_kitten + average_complexity_anchor_panda)/expected_no_other
        expected_average_frequency_aerospace = (frequency_aeroblade + frequency_apt3 + frequency_turbine_panda)/expected_no_aerospace
        expected_average_frequency_other = (frequency_imperial_kitten + frequency_anchor_panda)/expected_no_other

        actual_average_frequency_aerospace,actual_average_frequency_other, actual_average_complexity_aerospace, actual_average_complexity_other = ATTandCKProbablisticModel.techniquecomplexity.calculate_complexity(techniques_to_tactics_array, threat_actor_names_array)
        self.assertEqual([actual_average_frequency_aerospace,actual_average_frequency_other, actual_average_complexity_aerospace, actual_average_complexity_other],[expected_average_frequency_aerospace,expected_average_frequency_other,expected_complexities_aerospace,expected_complexities_other],'Error in calculation')
if __name__ == '__main__':
    unittest.main()