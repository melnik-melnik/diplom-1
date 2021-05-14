import datetime
import pymongo
from bson import ObjectId
from db_con import db_client, db_sessions_col, db_susp_session, db_archive_pkt_col, db_white_list, db_chats_id
from main_module import sniff


# ------------------------------------------------------------------#
#               Home page                                           #
# ------------------------------------------------------------------#

def timeline_diagrams(start, end):
    try:
        dict_pkt = []
        temp_dict_subdmn = {'dns_names': {}}
        count_sum_pkt = 0
        count_susp_pkt = 0
        for doc in db_sessions_col.find({'start_time': {'$gte': start, '$lt': end}}):
            for key, val in doc['clients'].items():
                count_sum_pkt += val['pkt_count']
                count_susp_pkt += val['susp_pkt']
        dict_pkt.append({'ip': key, 'pkt_count': count_sum_pkt, 'susp_pkt': count_susp_pkt})

        for doc in db_sessions_col.find({'start_time': {'$gte': start, '$lt': end}}):
            for key, val in doc['dns_names'].items():
                temp_dict_subdmn['dns_names'].update({key: {
                    'count_queries': temp_dict_subdmn['dns_names'][key]['count_queries'] + val['count_queries'] if (
                            temp_dict_subdmn['dns_names'].get(key) is not None) else val['count_queries']
                    , 'subdomains': temp_dict_subdmn['dns_names'][key]['subdomains'] + len(val['subdomains']) if (
                            temp_dict_subdmn['dns_names'].get(key) is not None) else len(val['subdomains'])
                }})

        dict_subdmn = []
        for key, val in temp_dict_subdmn['dns_names'].items():
            dict_subdmn.append(
                {'dns_names': key, 'count_queries': val['count_queries'], 'subdomains': val['subdomains']})

        sort_dict_subdmn = sorted(dict_subdmn, key=lambda k: k['subdomains'], reverse=True)

        return dict_pkt, sort_dict_subdmn
    except:
        pass


def last_session_diagrams():
    try:
        last = db_sessions_col.find().sort('$natural', pymongo.DESCENDING).limit(-1).next()

        count_pkt = [{'ip': key, 'pkt_count': val['pkt_count'], 'susp_pkt': val['susp_pkt']} for key, val in
                     last['clients'].items()]  # кол-во пакетов у клиентов

        count_subdmn = [{'dns_names': key, 'subdomains': len(val['subdomains'])} for key, val in
                        last['dns_names'].items()]  # кол-во поддоменов

        sort_dict_subdmn = sorted(count_subdmn, key=lambda k: k['subdomains'], reverse=True)

        return count_pkt, sort_dict_subdmn
    except:
        pass


# ------------------------------------------------------------------#
#               View traffic page                                   #
# ------------------------------------------------------------------#

def output_susp_traffic():
    susp_sessions = db_susp_session.find()

    for ses in susp_sessions:
        ip = str(ses["ip"]).replace('_', '.')
        result = db_archive_pkt_col.find({
            "$and": [
                {"$or": [{"src": ip}, {"dst": ip}]},
                {"ses_id": ses["ses_id"]}
            ]
        })

    dict_type = {'A': 1,
                 'AAAA': 28,
                 'AFSDB': 18,
                 'APL': 42,
                 'CAA': 257,
                 'CDNSKEY': 60,
                 'CDS': 59,
                 'CERT': 37,
                 'CNAME': 5,
                 'CSYNC': 62,
                 'DHCID': 49,
                 'DLV': 32769,
                 'DNAME': 39,
                 'DNSKEY': 48,
                 'DS': 43,
                 'EUI48': 108,
                 'EUI64': 109,
                 'HINFO': 13,
                 'HIP': 55,
                 'IPSECKEY': 45,
                 'KEY': 25,
                 'KX': 36,
                 'LOC': 29,
                 'MX': 15,
                 'NAPTR': 35,
                 'NS': 2,
                 'NSEC': 47,
                 'NSEC3': 50,
                 'NSEC3PARAM': 51,
                 'OPENPGPKEY': 61,
                 'PTR': 12,
                 'RRSIG': 46,
                 'RP': 17,
                 'SIG': 24,
                 'SMIMEA': 53,
                 'SOA': 6,
                 'SRV': 33,
                 'SSHFP': 44,
                 'TA': 32768,
                 'TKEY': 249,
                 'TLSA': 52,
                 'TSIG': 250,
                 'TXT': 16,
                 'URI': 256,
                 'ZONEMD': 63,
                 'SVCB': 64,
                 'HTTPS': 65,
                 'MD': 3,
                 'MF': 4,
                 'MAILA': 254,
                 'MB': 7,
                 'MG': 8,
                 'MR': 9,
                 'MINFO': 14,
                 'MAILB': 253,
                 'WKS': 11,
                 'NB': 32,
                 'NBSTAT': 33,
                 'NULL': 10,
                 'A6': 38,
                 'NXT': 30,
                 'KEY': 25,
                 'SIG': 24,
                 'HINFO': 13,
                 'RP': 17,
                 'X25': 19,
                 'ISDN': 20,
                 'RT': 21,
                 'NSAP': 22,
                 'NSAP-PTR': 23,
                 'PX': 26,
                 'EID': 31,
                 'NIMLOC': 32,
                 'ATMA': 34,
                 'APL': 42,
                 'SINK': 40,
                 'GPOS': 27,
                 'UINFO': 100,
                 'UID': 101,
                 'GID': 102,
                 'UNSPEC': 103,
                 'SPF': 99,
                 'NINFO': 56,
                 'RKEY': 57,
                 'TALINK': 58,
                 'NID': 104,
                 'L32': 105,
                 'L64': 106,
                 'LP': 107,
                 'DOA': 259, }

    dict_out = []
    for val in result:
        dict_out.append(
            {'label': val['label'], 'src': val['src'], 'dst': val['dst'], 'len': val['len'], 'qr': val['qr'],
             'count_queries': val['count_queries'],
             'qry_name': val['qry_name'], 'qry_type': val['qry_type'], 'resp_type': val['resp_type'],
             'resp_ttl': val['resp_ttl'], 'resp_len': val['resp_len'],
             'count_auth_rr': val['count_auth_rr'], 'count_add_rr': val['count_add_rr'],
             'count_answers': val['count_answers']
             })

    return dict_out


'''
def search_traffic():
    db_operations.create_index([('Name', 'text')])
    #users = db_operations.find({'$all': {'$in': ['*' + insert_name + '*']}})
    users = db_operations.find({"$text": {"$search": insert_name}})
    output = [{'Name': user['Name'], 'Entropy': user['Entropy']} for user in users]
    print('search_traffic: ', output)
    return
'''


# ------------------------------------------------------------------#
#               White list page                                     #
# ------------------------------------------------------------------#


def find_white_list():
    white_list_names = db_white_list.find()
    output = [{'id': el['_id'], 'name': el['name']} for el in white_list_names]
    return output


def insert_white_list(insert_name):
    db_white_list.insert_one({"name": insert_name})
    sniff.update_white_list()
    return


def search_white_list(insert_name):
    db_white_list.create_index([('name', 'text')])
    users = db_white_list.find({"$text": {"$search": insert_name}})
    output = [{'id': user['_id'], 'name': user['name']} for user in users]
    print('search_white_list: ', output)
    return output


def delete_white_list(id):
    db_white_list.delete_one({"_id": ObjectId(id)})
    sniff.update_white_list()
    return


# ------------------------------------------------------------------#
#               White list page                                     #
# ------------------------------------------------------------------#

def insert_chat_id(id):
    db_chats_id.insert_one({"chat_id": id})

'''
def save_chat_id(chat_id):
    login = 
    db_login.update({"login": {"$eq": login}}, {"$push": {"chat_id": chat_id}})
'''
