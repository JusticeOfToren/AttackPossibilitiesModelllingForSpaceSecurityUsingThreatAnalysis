#!/usr/bin/env python3
"""
Module Name: lightgbmmodelling-classifier.py
Description: Creates and allows predictions from lightgbm machine learning model
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import pandas as pd
from sklearn.model_selection import train_test_split
import lightgbm
from sklearn.metrics import roc_auc_score, RocCurveDisplay, ConfusionMatrixDisplay, classification_report, accuracy_score, f1_score
import matplotlib.pylab as plt
import csv
import json
import time
import numpy as np
from urllib.request import Request, urlopen
from urllib.error import HTTPError
X = pd.read_pickle('./CVEML/storex.pkl')
y = pd.read_pickle('./CVEML/storey.pkl')
import pandasdataframebuild
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train.shape, X_test.shape, y_train.shape, y_test.shape

train_data = lightgbm.Dataset(X_train, label=y_train, categorical_feature=['cwe','attackvector','attackcomplexity','privsreq','userinteraction','scope','confidentialityreq','integrityreq','availreq'])
test_data = lightgbm.Dataset(X_test, label=y_test, categorical_feature=['cwe','attackvector','attackcomplexity','privsreq','userinteraction','scope','confidentialityreq','integrityreq','availreq'])

parameters = {'objective':'binary', # Optuna determined the best parameters
              'metric':'auc',
              
              'is_unbalance':'true',
              'boosting':'gbdt',
              'num_leaves': 246,
              'feature_fraction': 0.9965802844053524,
              'bagging_fraction': 0.9833774716278665,
              'bagging_freq':21,
              'learning_rate':0.01783096810577505,
              'verbose':-1}

fit_params ={
    'categorical_feature':'name:cwe,attackvector,attackcomplexity,privsreq,userinteraction,scope,confidentialityreq,integrityreq,availreq'
}
model = lightgbm.LGBMClassifier(max_depth=-5,random_state=42, **parameters)
model.fit(X_train,y_train,eval_set=[(X_test,y_test),(X_train,y_train)],eval_metric='logloss', **fit_params)
user_input = input("Input 1 for model evaluation, input 2 for CVE prediction")
if user_input == "1":
    y_predict=model.predict(X_test)
    print('LightGBM Model accuracy score: {0:0.4f}'.format(accuracy_score(y_test, y_predict)))
    print('LightGBM Model f1-score: {0:0.4f}'.format(f1_score(y_test, y_predict)))
    print('LightGBM Model ROC AUC Score: {0:0.4f}'.format(roc_auc_score(y_test, y_predict)))
    # model_lgbm = lightgbm.train(parameters, train_data, valid_sets=valid_data, num_boost_round=5000)
    # y_train_pred = model_lgbm.predict(X_train)
    # y_valid_pred = model_lgbm.predict(X_valid)
    print('Training accuracy {:.4f}'.format(model.score(X_train,y_train)))
    print('Testing accuracy {:.4f}'.format(model.score(X_test,y_test)))
    print(classification_report(y_test,model.predict(X_test),digits=4))
    lightgbm.plot_importance(model, title="LightGBM Feature Importance", max_num_features=20, figsize=(8, 6))
    # plt.show()
    # RocCurveDisplay.from_predictions(y_test,y_predict)
    # ConfusionMatrixDisplay.from_predictions(y_test,y_predict)
    plt.show()
else:
    # This section builds the feature set for a given CVE and feeds it to the model for prediction
    cve_to_test = input("Input CVE for prediction: ")
    print("This product uses the NVD API but is not endorsed or certified by the NVD.")
    try:
        entry = {}
        nvd_request=Request("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(cve_to_test))
        api_return = urlopen(nvd_request)
        encoding = api_return.info().get_content_charset('utf-8')
        api_return_read = api_return.read()
        nvd_json_object = json.loads(api_return_read.decode(encoding))
        description = ""
        weaknesses = []
        jcount=0
        attackvectordict = {"NETWORK":0,"ADJACENT_NETWORK":1,"LOCAL":2,"PHYSICAL":3}
        attackcomplexitydict = {"LOW":0, "HIGH":1}
        privsreqdict = {"NONE":0,"LOW":1,"HIGH":2}
        userinteractiondict = {"NONE":0,"REQUIRED":1}
        scopedict = {"UNCHANGED":0, "CHANGED":1}
        condict = {"NONE":0,"LOW":1,"HIGH":2}
        intdict = {"NONE":0,"LOW":1,"HIGH":2}
        availdict = {"NONE":0,"LOW":1,"HIGH":2}
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
        entry["cwe"] = int(weaknesses[0].replace('CWE-',''))
        icount = 0
        for i in nvd_json_object['vulnerabilities'][0]['cve']['descriptions']:
            if i['lang'] == "en":
                description += " " + nvd_json_object['vulnerabilities'][0]['cve']['descriptions'][icount]['value']
                continue
            icount+=1
        desc = ''.join(ch for ch in description if ch.isalnum() or ch == " ")
        entry["basescore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        entry["attackvector"] = attackvectordict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']]
        entry["attackcomplexity"] = attackcomplexitydict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']]
        entry["privsreq"] = privsreqdict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']]
        entry["userinteraction"] = userinteractiondict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']]
        entry["scope"] = scopedict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['scope']]
        entry["confidentialityreq"] = condict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['confidentialityImpact']]
        entry["integrityreq"] = intdict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['integrityImpact']]
        entry["availreq"] = availdict[nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['availabilityImpact']]
        entry["exploitscore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
        entry["impactscore"] = nvd_json_object['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['impactScore']
        # Get EPSS score and percentile
        epss_request=Request("https://api.first.org/data/v1/epss?cve={}".format(cve_to_test))
        api_return_3 = urlopen(epss_request)
        encoding_3 = api_return_3.info().get_content_charset('utf-8')
        api_return_read_3 = api_return_3.read()
        epss_json_object = json.loads(api_return_read_3.decode(encoding_3))
        entry['epssscore'] = float(epss_json_object['data'][0]['epss'])
        entry['epsspercentile'] = float(epss_json_object['data'][0]['percentile'])
        with open('Datasets/lightgbmpredictfile.csv','w', newline='') as csvfile:
            fieldnames = ['cwe','basescore','attackvector','attackcomplexity','privsreq','userinteraction','scope','confidentialityreq','integrityreq','availreq','exploitscore','impactscore', 'epssscore','epsspercentile']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(entry)
        df_test = pd.read_csv("Datasets/lightgbmpredictfile.csv")
        var_columns = [c for c in df_test.columns]
        desc = pandasdataframebuild.text_converter(desc)
        desc = np.array(desc)
        vector_dict = {}
        for i in range(512):
             vector_dict[str(i)] = desc[i]
        Xpredict = df_test.loc[:, var_columns]
        Xpredict = Xpredict.assign(**vector_dict)
        Xpredict.shape
        for i in range(50):
             print("")
        y_predict=model.predict(Xpredict)
        if y_predict[0] == 0:
             print("Prediction: CVE is not used by an aerospace attacker")
        else:
             print("Prediction: CVE is used by an aerospace attacker")
        print(y_predict)
    except Exception as e:
         print("Failed to retrieve data for the input CVE: {}".format(e))