#!/usr/bin/env python3
"""
Module Name: cvecounter.py
Description: Counts the number of CVEs in the aerospace and general sets
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import csv

aerospace = 0
nonaerospace = 0
with open('Datasets/cvefeatures.csv', mode ='r')as file:
  csvFile = csv.reader(file)
  next(csvFile, None)
  for cve in csvFile:
        if cve[14] == '0':
            nonaerospace+=1
        else:
            aerospace+=1
print("{} CVEs in aerospace".format(aerospace))
print("{} CVEs outside of aerospace".format(nonaerospace))
print("{} CVEs total".format(aerospace+nonaerospace))