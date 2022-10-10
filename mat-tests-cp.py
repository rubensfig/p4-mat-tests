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

bfrt_info = interface.bfrt_info_get("mat-tests-mat")
interface.bind_pipeline_config(p4_name=bfrt_info.p4_name)

sessions = Session.read_sessions_from_file("./sessions.json")

LIMIT = 4096

PORTS = [
288,
292,
296,
300,
304,
308,
312,
316,
156,
152,
148,
144,
140,
136,
132,
128,
  0,
  4,
  8,
 12,
 16,
 20,
 24,
 28,
444,
440,
436,
432,
428,
424,
420,
416,
176,
180,
184,
188,
172,
284,
280,
276,
272,
268,
400,
404,
408,
412,
396,
 60,
 56,
 52,
 48,
 44,
260,
]

for i in ports: 

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

