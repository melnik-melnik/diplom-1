import pyshark
import pandas as pd
import csv
import math


def parse_doc_pkt(pkt):
    result = [
        pkt['len'], pkt['qr'], pkt['count_queries'], pkt['qry_type'],
        dns_name(pkt['qry_name']),
        len(pkt['qry_name']), pkt['count_labels'], pkt['resp_type'],
        pkt['resp_ttl'], pkt['resp_len'], pkt['count_auth_rr'],
        pkt['count_add_rr'], pkt['count_answers'], pkt['count_rtypes']
    ]
    return result

def parse_pcap_to_df(filename,label):
    capture = pyshark.FileCapture(input_file=filename,
                                  display_filter='dns')
    df=pd.DataFrame(columns=[
            'label', 'len', 'qr', 'count_queries', 'qry_type',
            'qry_name_enthropy', 'qry_name_len', 'count_labels', 'resp_type',
            'resp_ttl', 'resp_len', 'count_auth_rr', 'count_add_rr',
            'count_answers', 'count_rtypes'
        ])
    print('pkt start')
    for pkt in capture:

        try:
            result = {
                'label': label,
                'len': pkt.ip.len,
                'qr': pkt.dns.flags_response,
                'count_queries': pkt.dns.count_queries,
                'qry_type': pkt.dns.qry_type,
                'qry_name_enthropy': dns_name(pkt.dns.qry_name),
                'qry_name_len': pkt.dns.qry_name_len,
                'count_labels': pkt.dns.count_labels
            }
            if pkt.dns.flags_response == '1':
                attributes = pkt.dns.field_names
                r_types = [
                    'a', 'aaaa', 'cname', 'txt', 'ns', 'mx', 'soa',
                    'dnskey'
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
            else:
                result.update({
                    'resp_type': 0,
                    'resp_ttl': 0,
                    'resp_len': 0,
                    'count_auth_rr': 0,
                    'count_add_rr': 0,
                    'count_answers': 0,
                    'count_rtypes': 0
                })
            df = df.append(result, ignore_index=True)
        except:
            pass

    return df
def parse_pcap_to_csv(filename,output_filename,label):
    with open(output_filename, 'w') as csvfile:
        capture = pyshark.FileCapture(input_file=filename,
                                      display_filter='dns')
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow([
            'label', 'len', 'qr', 'count_queries', 'qry_type',
            'qry_name_enthropy', 'qry_name_len', 'count_labels', 'resp_type',
            'resp_ttl', 'resp_len', 'count_auth_rr', 'count_add_rr',
            'count_answers', 'count_rtypes'
        ])
        for pkt in capture:
            try:
                result = {
                    'label': label,
                    'len': pkt.ip.len,
                    'qr': pkt.dns.flags_response,
                    'count_queries': pkt.dns.count_queries,
                    'qry_type': pkt.dns.qry_type,
                    'qry_name_enthropy': dns_name(pkt.dns.qry_name),
                    'qry_name_len': pkt.dns.qry_name_len,
                    'count_labels': pkt.dns.count_labels
                }
                if pkt.dns.flags_response == '1':
                    attributes = pkt.dns.field_names
                    r_types = [
                        'a', 'aaaa', 'cname', 'txt', 'ns', 'mx', 'soa',
                        'dnskey'
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
                else:
                    result.update({
                        'resp_type': 0,
                        'resp_ttl': 0,
                        'resp_len': 0,
                        'count_auth_rr': 0,
                        'count_add_rr': 0,
                        'count_answers': 0,
                        'count_rtypes': 0
                    })
                csvwriter.writerow(result.values())
            except:
                pass


def dns_name(name):
    slen = len(name)
    freqs = (float(name.count(c)) / slen for c in set(name))
    return -sum((prob * math.log(prob, 2.0) for prob in freqs))
