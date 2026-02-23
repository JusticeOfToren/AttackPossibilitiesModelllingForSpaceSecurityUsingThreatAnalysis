#!/usr/bin/env python3
"""
Module Name: pandasdataframebuild.py
Description: Converts descriptions to vectors and creates pickle files
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

import numpy as np
import pandas as pd
from rake_nltk import Rake
import tensorflow as tf
import tensorflow_hub as hub
import nltk
nltk.download('stopwords')
nltk.download('punkt_tab')
# https://youtu.be/SW3akc0ho7M?si=qusWpgi98a3wFnC_
import matplotlib.pylab as plt

'''Converts the text from the CVE and CWE into vectors that LightGBM can process'''
def text_converter(text):
    # Use the RAKE algorithm to convert the description into keywords
    r = Rake()
    r.extract_keywords_from_text(text)
    # Use https://medium.com/@sebastiencallebaut/classifying-tweets-with-lightgbm-and-the-universal-sentence-encoder-2a0208de0424 to convert keywords text to vectors
    keyword_test = r.get_ranked_phrases()
    text_to_vectorise=""
    for words in keyword_test:
        text_to_vectorise += " " + words
    # print(texttovectorise)
    use = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
    emb = use([text_to_vectorise])
    review_emb = tf.reshape(emb, [-1]).numpy()
    return review_emb


'''Converts the given vector array into a 512 vector dictionary'''
def create_vector_dictionary(vector_array):
    vector_dict = {}
    for k in range(512):
        vector_dict[str(k)] = []
    for vector in vector_array:
        for j in range(512):
            vector_dict[str(j)].append(vector[j])
    return vector_dict

def generate_pickles():
    description_append = []
    df_train = pd.read_csv("Datasets/cvemldataset.csv")
    for i, description in enumerate(df_train['description']):
        description_append.append(text_converter(description))
        if i % 50 == 0:
            print("{} records generated".format(i))
    description_append = np.array(description_append)
    var_columns = [c for c in df_train.columns if c not in ['name','aerospace','description']]
    vector_dict = create_vector_dictionary(description_append)
    X = df_train.loc[:, var_columns]
    X = X.assign(**vector_dict)
    y = df_train.loc[:,'aerospace']
    '''As this program was memory intensive enough to require the use of HPC resources, the outputs are pickled so that they can be used by other programs without the same memory requirement'''
    X.to_pickle('storex.pkl')
    y.to_pickle('storey.pkl')

if __name__ == '__main__': # Only execute when this file is called, allows unit testing to run without executing the full program
    generate_pickles()