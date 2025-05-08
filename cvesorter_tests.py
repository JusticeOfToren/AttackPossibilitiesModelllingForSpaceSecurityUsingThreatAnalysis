#!/usr/bin/env python3
"""
Module Name: cvesorter_tests.py
Description: Tests cvesorter
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import CVEFeatureCreation.cvesorter
import os
here = os.path.dirname(os.path.abspath(__file__))

class Tests(unittest.TestCase):
    def test_datasetcreator(self):
        not_in_cve, in_cve = CVEFeatureCreation.cvesorter.dataset_creator(os.path.join(here, 'Datasets/known_exploited_vulns_unit_test.csv'),os.path.join(here, 'Datasets/CVEUnitTest.xlsx'))
        technique_intersection = set(not_in_cve) & set(in_cve)
        self.assertEqual(len(technique_intersection),0, 'CVEs in both lists')
        len_total_expected = 10 + 10 - 1 # There are 10 CVEs in each test set, with one shared between both
        len_total_actual = len(not_in_cve)+len(in_cve)
        self.assertEqual(len_total_actual,len_total_expected, 'Not all CVEs in lists')

    def test_datasetcreator_actual(self):
        not_in_cve, in_cve = CVEFeatureCreation.cvesorter.dataset_creator()
        len_total_actual = len(not_in_cve)+len(in_cve)
        print(len_total_actual)
        self.assertEqual(len_total_actual,1408, 'Not all CVEs in lists')
if __name__ == '__main__':
    unittest.main()