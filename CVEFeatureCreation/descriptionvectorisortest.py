#!/usr/bin/env python3
"""
Module Name: descriptionvectorisortest.py
Description: Creates the rake output example used in the research paper
Author: Benjamin McCullough
Date: Last Updated: 24/04/2025
Version: 1.0
"""

from rake_nltk import Rake
import tensorflow as tf
import tensorflow_hub as hub
import nltk
nltk.download('stopwords')
nltk.download('punkt_tab')
# import tensorflow_text
# from tensorflow.keras.optimizers import Adam, SGD
# from tensorflow.keras.layers import Dense, Input, BatchNormalization, Dropout, Concatenate
# from tensorflow.keras.models import Model, Sequential
# from tensorflow.keras.callbacks import ModelCheckpoint
def textconverter(text):
    # Use the RAKE algorithm to convert the description into keywords
    r = Rake()
    r.extract_keywords_from_text(text)
    # Use https://medium.com/@sebastiencallebaut/classifying-tweets-with-lightgbm-and-the-universal-sentence-encoder-2a0208de0424 to convert keywords text to vectors
    keyword_test = r.get_ranked_phrases()
    texttovectorise=""
    for words in keyword_test:
        texttovectorise += " " + words
    print(texttovectorise)
    use = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
    emb = use([texttovectorise])
    review_emb = tf.reshape(emb, [-1]).numpy()
    return review_emb
textconverter("The product does not properly assign modify track or check privileges for an actor creating an unintended sphere of control for that actor The product does not properly assign modify track or check privileges for an actor creating an unintended sphere of control for that actor VMware Fusion 11x before 1152 VMware Remote Console for Mac 11x and prior before 1101 and Horizon Client for Mac 5x and prior before 540 contain a privilege escalation vulnerability due to improper use of setuid binaries Successful exploitation of this issue may allow attackers with normal user privileges to escalate their privileges to root on the system where Fusion VMRC or Horizon Client is installed")