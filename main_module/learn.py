import time
import pymongo
import datetime
from sklearn.decomposition import PCA
from sklearn.preprocessing import OrdinalEncoder, LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve, roc_auc_score, recall_score, precision_score
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import train_test_split
from statsmodels.stats.outliers_influence import variance_inflation_factor
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.naive_bayes import GaussianNB
import pandas as pd
import pickle
from sklearn.pipeline import Pipeline
from main_module import ses


def create_model(good_traffic, mal_traffic):
    '''
    df=good_traffic
    df.to_csv('qwe.csv',index=False)
    df=pd.read_csv('qwe.csv')
    df = df.append(pd.read_csv(mal_traffic),ignore_index=True)
    '''
    df = pd.read_csv('./dataframe.csv')

    X_train, X_test, y_train, y_test = train_test_split(df.drop('label',
                                                                axis=1),
                                                        df['label'],
                                                        test_size=0.3,
                                                        random_state=143)

    pipeline = Pipeline(
        [('pca', PCA(n_components = 2)), ('scaler', StandardScaler()), ('classifier', SVC(kernel='linear', random_state=50, probability=True))])
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    y_pred_gnb = pipeline.predict(X_test)
    y_prob_pred_gnb = pipeline.predict_proba(X_test)
    # how did our model perform?
    count_misclassified = (y_test != y_pred_gnb).sum()
    print("SVC")
    print("=" * 30)
    print('Misclassified samples: {}'.format(count_misclassified))
    accuracy = accuracy_score(y_test, y_pred_gnb)
    print('Accuracy: {:.2f}'.format(accuracy))
    print(classification_report(y_test, y_pred_gnb))
    with open('./gnb.clf', 'wb') as fid:
        pickle.dump(pipeline, fid)
    print('обуч')
    ses.predictor.change_classificator()
