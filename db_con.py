from pymongo import MongoClient

db_client = MongoClient('mongodb://localhost')
db_pkt_col_packets = db_client['Project']['Packets']
db_sessions_col = db_client['Project']['Sessions']
db_archive_pkt_col = db_client['Project']['Archive_pkt']
db_login = db_client['Project']['Users']
db_susp_session = db_client['Project']['Susp_session']
db_white_list = db_client['Project']['White_list']
db_chats_id = db_client['Project']['Chats_id']

