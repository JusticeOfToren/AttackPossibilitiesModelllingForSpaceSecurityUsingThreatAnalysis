#!/usr/bin/env python3
"""
Module Name: cwetopxcalculator_tests.py
Description: Tests cwetopxcalculator
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import CWETopX.cwetopxcalculator
import os
here = os.path.dirname(os.path.abspath(__file__))

class Tests(unittest.TestCase):
    def test_create_occur_dict(self):
        expected_occur_dict = {'CWE-36':11,'CWE-22':10,'CWE-20':9,'CWE-917':8,
                               'CWE-197':7,'CWE-787':6,'CWE-782':5,'CWE-416':4,
                               'CWE-190':3,'CWE-284':2,'CWE-306':1}
        actual_occur_dict = CWETopX.cwetopxcalculator.create_occur_dict('Datasets/cvefeatures_test.csv')
        self.assertEqual(expected_occur_dict, actual_occur_dict, 'Incorrect occurance dictionary')

    def test_print_top_10(self):
        expected_top_cwe=['CWE-36','CWE-22','CWE-20','CWE-917',
                               'CWE-197','CWE-787','CWE-782','CWE-416',
                               'CWE-190','CWE-284']
        actual_occur_dict = CWETopX.cwetopxcalculator.create_occur_dict('Datasets/cvefeatures_test.csv')
        actual_top_cwe = CWETopX.cwetopxcalculator.print_top_ten(actual_occur_dict)
        self.assertEqual(actual_top_cwe, expected_top_cwe, 'Incorrect top 10')
if __name__ == '__main__':
    unittest.main()