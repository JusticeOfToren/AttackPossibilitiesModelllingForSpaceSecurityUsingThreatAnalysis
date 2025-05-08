#!/usr/bin/env python3
"""
Module Name: performancetestattribution.py
Description: Performance tests attribution calculation
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import time
import calculateattribution
from stix2 import FileSystemSource
attack_string = ["T1598","T1053.003", "T1078.003","T1211","T1595","T1021","T1590.004","T1210","T1078.001","T1543","T003","T005","T1059","T1569","T1543.003","T1070","T1553","T1082","T1021.002", "T1016"]
attack_string_length = 20
src = FileSystemSource('./cti-master/enterprise-attack') # The ATT&CK CTI enterprise dataset, used to get the tactic for each technique
exec_times = []
for i in range(attack_string_length):
    current_attack_string = attack_string[0:i+1]
    start = time.time()
    calculateattribution.calculate_attribution(src,current_attack_string)
    end = time.time()
    exec_times.append([i+1,end-start])
    print("Input size: {}, time to execute: {} seconds".format(i+1,end-start))
for i,j in exec_times: 
    print("Input size: {}, time to execute: {} seconds".format(i,j))