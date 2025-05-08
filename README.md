# ThreatActorAttribution

This is the project repository for the MEng Project: "Attack Possibilities Modelling for Space Security Using Threat Actor Analysis".
For installation instructions, read install-guide.txt. For replication instructions, read replication-guide.txt.
The purpose of the programs in this repository are to analyse data about threat actors to find information about protecting the space sector from cyber-attack.
The ATT&CKProbabalisticModel directory contains programs focused on the use of MITRE ATT&CK enterprise technique data.
The CVEFeatureCreation directory contains programs that prepare CVEs for machine learning modelling by retrieving data on them to form features.
The CVEML directory contains the programs required to create and run the machine learning model for CVEs. Within this directory, it is recommended to run pandasdataframebuild.py on a computer or cluster with at least 64Gb of RAM.
The CWETopX directory contains the program that determines the ten most frequent CWEs in aerospace.
At the top level of this repository, tatfloader.py is responsible for turning the ATT&CK datasets into python data structures.
The unit tests for the programs in the repo are also at the top level of the repository.

USAGE
Before use, follow installation instructions.
To predict whether a CVE will be used by an aerospace threat actor, run lightgbmmodelling-classifier.py and press 2 when prompted. Then input the CVE you want to check
To predict whether an attack was committed by a space threat actor, run calculateattribution.py with the command  python calculateattribution.py [number of techniques] [technique 1] [technique 2] etc