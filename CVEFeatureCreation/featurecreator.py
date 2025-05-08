#!/usr/bin/env python3
"""
Module Name: featurecreator.py
Description: Builds features for the CVE ML model
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import cvesorter
import csv
import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError
non_aerospace_cves, aerospace_cves = cvesorter.dataset_creator()
'''This product uses the NVD API but is not endorsed or certified by the NVD'''
cves_and_features = []
cves_needing_queried=[]


list_for_csv=[]
errors=[]
manual=[]
def request_rom_nvd(cve, aerospace):
    print("This product uses the NVD API but is not endorsed or certified by the NVD.")
    try:
        entry = {}
        nvd_request=Request("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(cve))
        nvd_request.add_header("apiKey", "f50b8996-9126-47f5-9f14-c533095d14b0")
        api_return = urlopen(nvd_request)
        encoding = api_return.info().get_content_charset('utf-8')
        api_return_read = api_return.read()
        nvd_json_object = json.loads(api_return_read.decode(encoding))
        description = ""
        entry["name"]=cve
        weaknesses = []
        jcount=0
        for j in nvd_json_object['vulnerabilities'][0]['cve']['weaknesses']:
            current_weakness = nvd_json_object['vulnerabilities'][0]['cve']['weaknesses'][jcount]['description'][0]['value']
            weaknesses.append(current_weakness)
            if current_weakness != 'NVD-CWE-noinfo' and current_weakness != 'NVD-CWE-Other':
                    current_weakness = int(current_weakness.replace('CWE-',''))
                    cwe_request=Request("https://cwe-api.mitre.org/api/v1/cwe/weakness/{}".format(current_weakness))
                    api_return_2 = urlopen(cwe_request)
                    encoding_2 = api_return_2.info().get_content_charset('utf-8')
                    api_return_read_2 = api_return_2.read()
                    cwe_json_object = json.loads(api_return_read_2.decode(encoding_2))
                    description += " " + cwe_json_object['Weaknesses'][0]['Description']
            jcount+=1
        entry["cwe"] = weaknesses
        icount = 0
        for i in nvd_json_object['vulnerabilities'][0]['cve']['descriptions']:
            if i['lang'] == "en":
                description += " " + nvd_json_object['vulnerabilities'][0]['cve']['descriptions'][icount]['value']
                continue
            icount+=1
        x = ''.join(ch for ch in description if ch.isalnum() or ch == " ")
        entry["description"] = x.strip() # Removes the newlines added by CWE description
        entry["basescore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        entry["attackvector"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
        entry["attackcomplexity"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
        entry["privsreq"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']
        entry["userinteraction"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']
        entry["scope"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['scope']
        entry["confidentialityreq"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['confidentialityImpact']
        entry["integrityreq"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['integrityImpact']
        entry["availreq"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['availabilityImpact']
        entry["exploitscore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
        entry["impactscore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['impactScore']
        entry["aerospace"] = aerospace
        # Get EPSS score and percentile
        epss_request=Request("https://api.first.org/data/v1/epss?cve={}".format(cve))
        api_return_3 = urlopen(epss_request)
        encoding_3 = api_return_3.info().get_content_charset('utf-8')
        api_return_read_3 = api_return_3.read()
        epss_json_object = json.loads(api_return_read_3.decode(encoding_3))
        entry['epssscore'] = epss_json_object['data'][0]['epss']
        entry['epsspercentile'] = epss_json_object['data'][0]['percentile']
        list_for_csv.append(entry)
        time.sleep(1)
    except KeyError as e:
        print(e)
        manual.append(cve)
    except IndexError as e:
        print(e)
        manual.append(cve)
    except HTTPError as e:
        print(e)
        manual.append(cve)
    except Exception as e:
            print(e)
            if e == "'cvssMetricV31'" or e == "HTTP Error 404: Not Found":
                manual.append(cve)
            else:
                time.sleep(15)
                request_rom_nvd(cve, aerospace)
timer = 0
full_counter=0
for cve in aerospace_cves:
    if timer < 48:
        request_rom_nvd(cve, 1)
        timer+=1
        full_counter+=1
    else:
        timer = 0
        full_counter+=1
        request_rom_nvd(cve, 1)
        print("{} down for aerospace".format(full_counter))

print("Aerospace CVEs completed")
timer = 0
full_counter=0
for cve2 in non_aerospace_cves:
    if timer < 48:
        request_rom_nvd(cve2, 0)
        timer+=1
        full_counter+=1
    else:
        timer = 0
        full_counter+=1
        request_rom_nvd(cve2, 0)
        print("{} down for non-aerospace".format(full_counter))


with open('../Datasets/cvefeatures.csv','w', newline='') as csvfile:
    field_names = ['name','cwe','description','basescore','attackvector','attackcomplexity','privsreq','userinteraction','scope','confidentialityreq','integrityreq','availreq','exploitscore','impactscore','aerospace','epssscore','epsspercentile']
    writer = csv.DictWriter(csvfile, fieldnames=field_names)
    writer.writeheader()
    writer.writerows(list_for_csv)


for i in manual:
    print(i)






notcvss3 = ["CVE-2009-2055", "CVE-2015-0666", "CVE-2012-0159", "CVE-2013-3918", "CVE-2013-0634", "CVE-2013-0633", "CVE-2013-3893", "CVE-2013-0808", "CVE-2015-3105", "CVE-2013-4979", "CVE-2014-4076", "CVE-2014-0515", "CVE-2013-1493", "CVE-2012-1875", "CVE-2012-0779", "CVE-2011-2110", "CVE-2013-3893"]