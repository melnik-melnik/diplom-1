import threading
import configparser
import sys
import os
import pyshark
from threading import Thread
from pprint import pprint
import datetime
import signal
import time
from collections import Counter

from pyshark.capture.capture import StopCapture
from db_con import db_client, db_pkt_col_packets, db_sessions_col, db_archive_pkt_col, db_login, db_white_list
import asyncio

# ['id', 'flags', 'flags_response', 'flags_opcode', 'flags_authoritative', 'flags_truncated', 'flags_recdesired', 'flags_recavail', 'flags_z', 'flags_authenticated', 'flags_checkdisable', 'flags_rcode', 'count_queries', 'count_answers', 'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 'qry_class', 'resp_name', 'resp_type', 'resp_class', 'resp_ttl', 'resp_len', 'cname', 'a', 'ns', 'response_to', 'time']
# ['id', 'flags', 'flags_response', 'flags_opcode', 'flags_truncated', 'flags_recdesired', 'flags_z', 'flags_checkdisable', 'count_queries', 'count_answers', 'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 'qry_class']
# ['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host']


class Sniffer(object):

    def update_white_list(self):
        self.res = [el['name'] for el in db_white_list.find()]

    def __init__(self, path_to_config):
        self.update_white_list()
        self.config = configparser.ConfigParser()
        self.config.read(path_to_config)
        #logger.setLevel(log_level[self.config['DEFAULT']['LOG_LEVEL']])
        #log_stream_handler = logging.StreamHandler(sys.stdout)
        #log_file_handler = logging.FileHandler('logs.log')
        #formatter = logging.Formatter( '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        #log_stream_handler.setFormatter(formatter)
        #logger.addHandler(log_stream_handler)
        #logger.debug('Init Complete')
        return None

    def decompile_packet(self, pkt):
        if self.run_flag == False:
            raise StopCapture()
        try:
            if '.'.join(pkt.dns.qry_name.split('.')[-2:]) in self.res:
                return
            result = {
                'src': pkt.ip.src,
                'dst': pkt.ip.dst,
                'len': pkt.ip.len,
                'qr': pkt.dns.flags_response,
                'count_queries': pkt.dns.count_queries,
                'qry_name': pkt.dns.qry_name,
                'qry_type': pkt.dns.qry_type,
                'count_labels': pkt.dns.count_labels
            }

            if pkt.dns.flags_response == '1':
                attributes = pkt.dns.field_names
                r_types = [
                    'a', 'aaaa', 'cname', 'txt', 'ns', 'mx', 'soa', 'dnskey'
                ]
                result.update({
                    'resp_type':
                        pkt.dns.resp_type,
                    'resp_ttl':
                        pkt.dns.resp_ttl,
                    'resp_len':
                        pkt.dns.resp_len,
                    'count_auth_rr':
                        pkt.dns.count_auth_rr,
                    'count_add_rr':
                        pkt.dns.count_add_rr,
                    'count_answers':
                        pkt.dns.count_answers,
                    'count_rtypes':
                        len([x for x in attributes if x in r_types])
                })
            elif pkt.dns.flags_response == '0':
                result.update({
                    'resp_type': 0,
                    'resp_ttl': 0,
                    'resp_len': 0,
                    'count_auth_rr': 0,
                    'count_add_rr': 0,
                    'count_answers': 0,
                    'count_rtypes': 0
                })
            self.send_to_db(result)
        except:
            pass

    def run_capture(self):
        self.run_flag = True

        while self.run_flag:
            try:
                '''interface=self.config['DEFAULT'],['INTERFACE']'''
                capture = pyshark.LiveCapture(display_filter='dns')
                capture.apply_on_packets(self.decompile_packet)
            except StopCapture:
                break

    @staticmethod
    def send_to_db(document=None):
        db_pkt_col_packets.insert_one(document)

    def stop_capture(self):
        self.run_flag = False
        pass
