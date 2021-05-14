from main_module import pkt_parse
from db_con import db_client, db_pkt_col_packets, db_sessions_col, db_archive_pkt_col, db_login, db_susp_session, db_chats_id
import time
import pymongo
import datetime
from sklearn.preprocessing import OrdinalEncoder, LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve, roc_auc_score, recall_score, precision_score
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import train_test_split
from statsmodels.stats.outliers_influence import variance_inflation_factor
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.naive_bayes import GaussianNB
import pandas as pd
from eventhandler import EventHandler
import pickle
from teleg_bot import send1


class Notification():
    @staticmethod
    def on_telegram_bot(msg):
        for client in db_chats_id.find():
            send1(client['chat_id'], msg)
        print('tunel')
        pass

    @staticmethod
    def send_to_mail():
        pass

    @staticmethod
    def send_to_alert():
        pass


class Session(object):
    def __init__(self):
        self.predictor = Predictor()
        self.notificator = EventHandler('add_notify')

    def start(self):
        self.run_flag = True
        while self.run_flag:
            self.session_handler()

    def add_notificator(self, func):
        self.notificator.link(func, 'add_notify')

    def remove_notificator(self, func):
        pass

    def stop(self):
        self.run_flag = False

    def check_session(self, client, ip, id):

        if client['pkt_count'] > 5 and client['susp_pkt'] / client['pkt_count'] > 0.1:
            db_susp_session.insert_one({"ses_id": id, "ip": ip})
            self.notificator.fire('add_notify', 'Обнаружено туннелирование с адреса ' + str(ip).replace('_', '.'))
            return 1
        return 0

    def stop_session(self):
        self.end_time = datetime.datetime.now()

    def session_handler(self):
        start_time = datetime.datetime.now()
        self.end_time = start_time + datetime.timedelta(minutes=1)
        self.session_doc = {
            'start_time': start_time,
            'end_time': '0',
            'clients': {},
            'dns_names': {}
        }

        id = db_sessions_col.insert_one(self.session_doc).inserted_id

        last = db_pkt_col_packets.find().sort(
            '$natural', pymongo.DESCENDING).limit(-1).next()
        last_id = last['_id']
        while datetime.datetime.now() < self.end_time:
            cursor = db_pkt_col_packets.find({'_id': {
                '$gt': last_id
            }})  # ,cursor_type=pymongo.CursorType.TAILABLE_AWAIT)
            # while cursor.alive:

            for doc in cursor:
                pred = self.predictor.predict_pkt(doc)
                doc["label"] = pred
                doc['ses_id'] = id
                doc.pop('_id', None)

                db_archive_pkt_col.insert_one(doc)

                last_id = doc['_id']
                ip = doc['src'] if doc['qr'] == '0' else doc['dst']
                ip = str(ip).replace('.', '_')

                self.session_doc['clients'].update({
                    ip: {
                        'pkt_count': 1,
                        'susp_pkt': 0,
                        'susp_event': 0
                    } if (self.session_doc['clients'].get(ip) is None) else {
                        'pkt_count':
                            self.session_doc['clients'][ip]['pkt_count'] + 1,
                        'susp_pkt':
                            self.session_doc['clients'][ip]['susp_pkt'] +
                            pred,
                        'susp_event':
                            self.check_session(self.session_doc['clients'][ip], ip, id)
                            if (self.session_doc['clients'][ip].get('susp_event') == 0) else 1
                    }
                })

                qry_name = '.'.join(doc['qry_name'].split('.')[-2:])
                qry_name = qry_name.replace('.', '_')
                self.session_doc['dns_names'].update({
                    qry_name: {
                        'count_queries': 1,
                        'subdomains': [doc['qry_name']]
                    } if (self.session_doc['dns_names'].get(qry_name) is None)
                    else {
                        'count_queries':
                            self.session_doc['dns_names'][qry_name]
                            ['count_queries'] + 1,
                        'subdomains':
                            self.session_doc['dns_names'][qry_name]['subdomains']
                            if (doc['qry_name'] in self.session_doc['dns_names']
                            [qry_name]['subdomains']) else
                            self.session_doc['dns_names'][qry_name]['subdomains'] +
                            [doc['qry_name']]
                    }
                })
                db_sessions_col.update_one({'_id': id},
                                           {'$set': self.session_doc}, upsert=False)
            time.sleep(1)
        self.session_doc['end_time'] = self.end_time
        db_sessions_col.update_one({'_id': id},
                                   {'$set': self.session_doc}, upsert=False)



class Predictor(object):
    def change_classificator(self):
        print('переобучил')
        with open('./gnb.clf', 'rb') as fid:
            self.clf = pickle.load(fid)

    def __init__(self):
        with open('./gnb.clf', 'rb') as fid:
            self.clf = pickle.load(fid)

    def predict_pkt(self, pkt=None):
        pkt = pkt_parse.parse_doc_pkt(pkt)
        print('pkt', int(self.clf.predict(np.array(pkt).reshape(1, -1))[0]))
        return int(self.clf.predict(np.array(pkt).reshape(1, -1))[0])
