#!/usr/bin/env python

import glob
import sys
import socket
import binascii
import os
import json
import ipaddress

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

def gen_mac_addresses():
    t = []
    for i in range(16):
        for j in range(256):
                t.append(mac_str_to_int((f"02:00:00:00:0{i:01x}:{j:02x}")))

    return t

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

bfrt_info = interface.bfrt_info_get("mat-tests-mat")
interface.bind_pipeline_config(p4_name=bfrt_info.p4_name)

for i in [288, 292, 296, 300, 304, 308]:
    #
    key = {
            '$DEV_PORT': i,
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
        'ig_intr_md.ingress_port': 288,
      }
data = {
        'port': 296
        }
data_action='a_set_port'
bfrt_add_entry(bfrt_info, target, 'table_1', data_action, key, data)
#

for tb in range(2, 12):
    for i in gen_mac_addresses():
        if tb != 2:
            #
            key = {
                    'hdr.ethernet.srcAddr': i,
                  }
        else:
            #
            key = {
                    'hdr.ethernet.srcAddr': i,
                    'meta.table_number': 2
                  }
        data = { }
        data_action='a_table' + str(tb)
        bfrt_add_entry(bfrt_info, target, 'table_' + str(tb), data_action, key, data)
        #



