#!/usr/bin/env python3
"""
Module Name: categoricalconverter.py
Description: Replaces categorical variables with their integer representations
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import csv
attackvectordict = {"NETWORK":0,"ADJACENT_NETWORK":1,"LOCAL":2,"PHYSICAL":3}
attackcomplexitydict = {"LOW":0, "HIGH":1}
privsreqdict = {"NONE":0,"LOW":1,"HIGH":2}
userinteractiondict = {"NONE":0,"REQUIRED":1}
scopedict = {"UNCHANGED":0, "CHANGED":1}
condict = {"NONE":0,"LOW":1,"HIGH":2}
intdict = {"NONE":0,"LOW":1,"HIGH":2}
availdict = {"NONE":0,"LOW":1,"HIGH":2}
listForCSV=[]
'''Takes each categorical value and replaces it with an integer representation'''
with open('../Datasets/cvefeatures.csv', mode ='r')as file: # Opens dataset created by featurecreator.py
  csvFile = csv.reader(file)
  next(csvFile, None)
  for cve in csvFile:
        entry={}
        entry["name"]=cve[0]
        weakness=0
        if cve[1] != "None":
            for j in eval(cve[1]):# CURRENTLY ONLY USING THE FIRST CWE MENTIONED
                if j != 'NVD-CWE-noinfo' and j != 'NVD-CWE-Other':
                    weakness = int(j.replace('CWE-',''))
                    break
        entry["cwe"] = weakness
        entry["description"] = " ".join(cve[2].split()) # Gets rid of extra spaces
        entry["basescore"] = cve[3]
        entry["attackvector"] = attackvectordict[cve[4]]
        entry["attackcomplexity"] = attackcomplexitydict[cve[5]]
        entry["privsreq"] = privsreqdict[cve[6]]
        entry["userinteraction"] = userinteractiondict[cve[7]]
        entry["scope"] = scopedict[cve[8]]
        entry["confidentialityreq"] = condict[cve[9]]
        entry["integrityreq"] = intdict[cve[10]]
        entry["availreq"] = availdict[cve[11]]
        entry["exploitscore"] = cve[12]
        entry["impactscore"] = cve[13]
        entry["aerospace"] = cve[14]
        entry["epssscore"] = cve[15]
        entry["epsspercentile"] = cve[16]
        print(entry)
        listForCSV.append(entry)


with open('../Datasets/cvemldataset.csv','w', newline='') as csvfile:
    fieldnames = ['name','cwe','description','basescore','attackvector','attackcomplexity','privsreq','userinteraction','scope','confidentialityreq','integrityreq','availreq','exploitscore','impactscore','aerospace', 'epssscore','epsspercentile']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(listForCSV)