#!/usr/bin/env python

import glob
import sys
import socket
import binascii
import os
import json
import ipaddress

class Session:
    def __init__(
        self, ip_address, client_mac, server_mac, outer_vlan, inner_vlan, pppoe_sid
    ):
        self.ip_address = ip_address
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.outer_vlan = outer_vlan
        self.inner_vlan = inner_vlan
        self.pppoe_sid = pppoe_sid

    def __str__(self):
        return str(self.__dict__)

    @staticmethod
    def from_dict(dict_obj):
        return Session(**dict_obj)

    @staticmethod
    def read_sessions_from_file(file_name):
        with open(file_name, "r") as sessions_file:
            json_obj = json.loads(sessions_file.read())
            return {
                key: Session.from_dict(value) for key, value in json_obj.items()
            }


bfrt_location = '{}/lib/python*/site-packages/tofino'.format( os.environ['SDE_INSTALL'])

sys.path.append(glob.glob(bfrt_location)[0])

import bfrt_grpc.client as gc

bfrt_ip = "127.0.0.1"
bfrt_port = "50052"

IG_PORT = 288
EG_PORT = 292

def mac_str_to_int(mac_address):
    return int(mac_address.replace(':', ''), 16)

def ip2int(addr):
    return int(binascii.hexlify(socket.inet_aton(addr)), 16)

def bfrt_add_entry(
    bfrt_info, target, table_name, action_name, key_dict={}, data_dict={}, is_default=False
):

    table_info = bfrt_info.table_get(table_name)

    key = []
    for k, v in key_dict.items():
        prefixlen = None

        if isinstance(v, list):
            if "prefixlen" in v[1]:
                key.append(gc.KeyTuple(k, v[0], prefix_len=v[2]))
            if "mask" in v[1]:
                key.append(gc.KeyTuple(k, v[0], mask=v[2]))
        else:
            key.append(gc.KeyTuple(k, v))

    key_tuple = table_info.make_key(key)

    data = []
    for k, v in data_dict.items():
        dt = None
        if isinstance(v, bool):
            data.append(gc.DataTuple(k, bool_val = v))
        elif isinstance(v, str):
            data.append(gc.DataTuple(k, str_val = v))
        else:
            data.append(gc.DataTuple(k, v))

    data_tuple = None
    if action_name:
        data_tuple = table_info.make_data(data, action_name)
    else:
        data_tuple = table_info.make_data(data)

    try:
        if is_default:
            table_info.default_entry_set(target, data_tuple)
        else:
            table_info.entry_add(target, [key_tuple], [data_tuple])
  
    except gc.BfruntimeReadWriteRpcException as error:
        return error

target = gc.Target(0) 

interface = gc.ClientInterface(
    "{}:{}".format(bfrt_ip, bfrt_port), client_id=0, device_id=0
)

bfrt_info = interface.bfrt_info_get("mat-tests")
interface.bind_pipeline_config(p4_name=bfrt_info.p4_name)

sessions = Session.read_sessions_from_file("./sessions.json")

LIMIT = 4096

#
key = {
        '$DEV_PORT': 288,
      }
data = {
        '$SPEED': 'BF_SPEED_100G',
        '$FEC': 'BF_FEC_TYP_REED_SOLOMON',
        '$PORT_ENABLE': True
        }
data_action=''
bfrt_add_entry(bfrt_info, target, '$PORT', data_action, key, data)
#

#
key = {
        '$DEV_PORT': 292,
      }
data = {
        '$SPEED': 'BF_SPEED_100G',
        '$FEC': 'BF_FEC_TYP_REED_SOLOMON',
        '$PORT_ENABLE': True
        }
data_action=''
bfrt_add_entry(bfrt_info, target, '$PORT', data_action, key, data)
#

for i, v in sessions.items():
    if int(i) > LIMIT:
        break
    #
    key = {
            'ig_intr_md.ingress_port': IG_PORT,
          }
    data = {
            'srcAddr': mac_str_to_int(v.client_mac)
            }
    data_action='a_set_port'
    bfrt_add_entry(bfrt_info, target, 'table_1', data_action, key, data)
    #

    #
    key = {
            'hdr.ethernet.srcAddr': mac_str_to_int(v.client_mac)
          }
    data = {
            'dstAddr': mac_str_to_int('ff:ff:ff:ff:ff:ff')
            }
    data_action='a_table2'
    bfrt_add_entry(bfrt_info, target,'table_2', data_action, key, data)
    #

#
key = {
        'hdr.ethernet.dstAddr': mac_str_to_int("ff:ff:ff:ff:ff:ff")
      }
data = {
        'etherType': 0x0800
        }
data_action='a_table3'
bfrt_add_entry(bfrt_info, target,'table_3', data_action, key, data)
#

#
key = {
        'hdr.ethernet.etherType': 0x0800
      }
data = {
         'protocol': 0x11
        }
data_action='a_table4'
bfrt_add_entry(bfrt_info, target,'table_4', data_action, key, data)
#

for  i, v in sessions.items():
    if int(i) > LIMIT:
        break
    #
    key = {
            'hdr.ipv4.protocol': 0x11
          }
    data = {
             'srcAddr': ip2int(v.ip_address)
            }
    data_action='a_table5'
    bfrt_add_entry(bfrt_info, target,'table_5', data_action, key, data)
    #

    #
    key = {
            'hdr.ipv4.srcAddr':ip2int(i.ip_address)
          }
    data = {
             'dstAddr': ip2int("10.71.33.131")
            }
    data_action='a_table6'
    bfrt_add_entry(bfrt_info, target,'table_6', data_action, key, data)
    #

#
key = {
        'hdr.ipv4.dstAddr': ip2int("10.71.33.131")
      }
data = {
         'srcPort':  21512
        }
data_action='a_table7'
bfrt_add_entry(bfrt_info, target,'table_7', data_action, key, data)
#

#
key = {
        'hdr.udp.srcPort': 2152
      }
data = {
         'dstPort': 2152
        }
data_action='a_table8'
bfrt_add_entry(bfrt_info, target,'table_8', data_action, key, data)
#

for i, v in sessions.items():
    if int(i) > 4096:
        break
    #
    key = {
            'hdr.udp.dstPort': 2152
          }
    data = {
             'teid': v.pppoe_sid
            }
    data_action='a_table9'
    bfrt_add_entry(bfrt_info, target,'table_9', data_action, key, data)
    #

    #
    key = {
            'hdr.gtp.teid': v.pppoe_sid
          }
    data = {
             'srcAddr': ip2int(ipaddress.ip_address("192.168.0.1") + v.pppoe_sid)
            }
    data_action='a_table10'
    bfrt_add_entry(bfrt_info, target,'table_10', data_action, key, data)
    #

    #
    key = {
             'hdr.ipv4_inner.srcAddr': ip2int(ipaddress.ip_address("192.168.0.1") + v.pppoe_sid)
          }
    data = {
            'port': EG_PORT,
            }
    data_action='set_egress_port'
    bfrt_add_entry(bfrt_info, target, 'table_11', data_action, key, data)
    #
