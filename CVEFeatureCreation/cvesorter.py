#!/usr/bin/env python3
"""
Module Name: cvesorter.py
Description: Uses datasets to build python data structures
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import csv
import pandas as pd
import os


here = os.path.dirname(os.path.abspath(__file__)) # https://stackoverflow.com/questions/21957131/python-not-finding-file-in-the-same-directory
def dataset_creator(filename=os.path.join(here, '../Datasets/known_exploited_vulnerabilities.csv'),cvexlsxfilename=os.path.join(here, '../Datasets/CVE.xlsx')):
    all_exploited_cves = []
    exploited_not_in_aerospace_cves = []
    with open(filename, encoding='utf-8') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count=0
        for row in csv_reader:
            if line_count == 0:
                # print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                # print(row[0])
                all_exploited_cves.append(row[0])
                exploited_not_in_aerospace_cves.append(row[0])
                line_count += 1
        # print(f'Processed {line_count} lines.')


    no_removed_from_list = 0
    aerospace_cves = []
    aerospace_cves_file = pd.read_excel(cvexlsxfilename,sheet_name='KnownUsedInAerospace')
    aerospace_cves_file = aerospace_cves_file.replace({float('nan'): None})
    norows = len(aerospace_cves_file)
    for col in aerospace_cves_file:
        if col == "CVE":
            for i in range(0, norows): # Pandas doesn't include title row in iteration
                current_cve = aerospace_cves_file[col][i]
                aerospace_cves.append(current_cve)
                if current_cve in exploited_not_in_aerospace_cves:
                    exploited_not_in_aerospace_cves.remove(current_cve)
                    # print("{} removed from list".format(current_cve))
                    no_removed_from_list += 1

    # print(no_removed_from_list)
    return exploited_not_in_aerospace_cves, aerospace_cves
