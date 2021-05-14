from flask import Flask
from app import app


'''
from main_module import pkt_parse, learn

res_pcap_to_df = './19 04 big traffic.pcapng'
mal_traffic = './mal_traf.csv'
learn.create_model(res_pcap_to_df, mal_traffic)
'''



print('main', __name__)
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run()