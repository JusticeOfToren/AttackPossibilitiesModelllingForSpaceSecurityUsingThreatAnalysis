# ThreatActorAttribution

This is the project repository for the MEng Project: "Attack Possibilities Modelling for Space Security Using Threat Actor Analysis".
For installation instructions, read install-guide.txt. For replication instructions, read replication-guide.txt.
The purpose of the programs in this repository are to analyse data about threat actors to find information about protecting the space sector from cyber-attack.
The ATT&CKProbabalisticModel directory contains programs focused on the use of MITRE ATT&CK enterprise technique data.
The CVEFeatureCreation directory contains programs that prepare CVEs for machine learning modelling by retrieving data on them to form features.
The CWETopX directory contains the program that determines the ten most frequent CWEs in aerospace.
At the top level of this repository, tatfloader.py is responsible for turning the ATT&CK datasets into python data structures.
The unit tests for the programs in the repo are also at the top level of the repository.

