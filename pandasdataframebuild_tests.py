#!/usr/bin/env python3
"""
Module Name: pandasdataframebuild_tests.py
Description: Tests pandasdataframebuild
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import unittest
import CVEML.pandasdataframebuild


class Tests(unittest.TestCase):
    def test_textconverter(self):
        actualoutput = CVEML.pandasdataframebuild.text_converter("Test text")
        self.assertEqual(len(actualoutput),512,'Incorrect length of input returned')

    def test_create_vector_dictionary(self):
        description_append = []
        for i, description in enumerate(['Hello','World','Testing']):
            description_append.append(CVEML.pandasdataframebuild.text_converter(description))
        actualoutput = CVEML.pandasdataframebuild.create_vector_dictionary(description_append)
        self.assertEqual(len(actualoutput),512,'Incorrect mapping')
        return
if __name__ == '__main__':
    unittest.main()