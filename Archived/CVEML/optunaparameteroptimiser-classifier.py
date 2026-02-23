#!/usr/bin/env python3
"""
Module Name: optunaparameteroptimiser-classifier.py
Description: Optimises hyperparameters for ml model
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import lightgbm
import optuna
import sklearn.metrics
from sklearn.metrics import roc_auc_score
import matplotlib.pylab as plt
# https://github.com/optuna/optuna-examples/blob/main/lightgbm/lightgbm_simple.py
X = pd.read_pickle('./CVEML/storex.pkl')
y = pd.read_pickle('./CVEML/storey.pkl')

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train.shape, X_test.shape, y_train.shape, y_test.shape
fit_params ={
    'categorical_feature':'name:cwe,attackvector,attackcomplexity,privsreq,userinteraction,scope,confidentialityreq,integrityreq,availreq'
}

def objective(trial):
    parameters = {'objective':'binary',
                'metric':'auc',
                'is_unbalance':'true',
                'boosting':'gbdt',
                'num_leaves': trial.suggest_int("num_leaves", 2, 1024),
                'feature_fraction': trial.suggest_float("feature_fraction", 0.1, 1.0),
                'bagging_fraction': trial.suggest_float("bagging_fraction", 0.1, 1.0),
                'bagging_freq':trial.suggest_int("bagging_freq", 1, 80),
                'learning_rate':trial.suggest_float("learning_rate", 0.005, 0.5),
                'verbose':-1}

    model = lightgbm.LGBMClassifier(max_depth=-5,random_state=42, **parameters)
    model.fit(X_train,y_train,eval_set=[(X_test,y_test),(X_train,y_train)],eval_metric='logloss', **fit_params)
    y_predict=model.predict(X_test)
    pred_labels = np.rint(y_predict)
    accuracy = sklearn.metrics.accuracy_score(y_test, pred_labels)
    return accuracy

study = optuna.create_study(direction="maximize")
study.optimize(objective, n_trials=500)

print("Number of finished trials: {}".format(len(study.trials)))

print("Best trial:")
trial = study.best_trial

print("  Value: {}".format(trial.value))

print("  Params: ")
for key, value in trial.params.items():
    print("    {}: {}".format(key, value))