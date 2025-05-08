#!/usr/bin/env python3
"""
Module Name: cwetopxcalculator.py
Description: Determines and outputs top 10 cwes in aerospace attackers
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import csv

'''https://stackoverflow.com/a/12343826'''
def key_with_max_val(d):
     """ a) create a list of the dict's keys and values; 
         b) return the key with the max value"""  
     v = list(d.values())
     k = list(d.keys())
     return k[v.index(max(v))]

def create_occur_dict(filename='Datasets/cvefeatures.csv'):
    occur_dict = {}
    with open(filename, mode ='r')as file:
        csv_file = csv.reader(file)
        next(csv_file, None)
        for cve in csv_file:
            cwes_current = [] # Prevents duplicate CWEs from affecting totals
            if cve[14] == '1':
                if cve[1] != "None":
                    for j in eval(cve[1]):
                        if j != 'NVD-CWE-noinfo' and j != 'NVD-CWE-Other':
                            if j not in occur_dict.keys() and j not in cwes_current:
                                occur_dict[j] = 1
                                cwes_current.append(j)
                            elif j not in cwes_current:
                                occur_dict[j] += 1
                                cwes_current.append(j)
                            else: # If the current CWE is recorded already for this CVE
                                continue
    return occur_dict
    
def print_top_ten(occur_dict):
    top_cwe = []
    print("-------------Top 10 CWEs in Aerospace--------------")
    for i in range(10):
        if len(occur_dict) == 0:
            print("All CWEs expended")
            break
        top_x_cwe=key_with_max_val(occur_dict)
        occurances=occur_dict[top_x_cwe]
        print("{}. {} with {} occurrences".format(i+1,top_x_cwe, occurances))
        occur_dict.pop(top_x_cwe)
        top_cwe.append(top_x_cwe)
        while True:
            if len(occur_dict) == 0:
                print("All CWEs expended")
                break
            top_x_cwe=key_with_max_val(occur_dict)

            if occur_dict[top_x_cwe] == occurances:
                print("{}. {} with {} occurrences".format(i+1,top_x_cwe, occurances))
                occur_dict.pop(top_x_cwe)
                top_cwe.append(top_x_cwe)
            else:
                break
    return top_cwe

if __name__ == '__main__':
    occur_dict = create_occur_dict()
    print_top_ten(occur_dict)