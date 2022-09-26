#!/usr/bin/env python

bfrt_ip = "127.0.0.1"
bfrt_port = "50052"

ING_PORT = 288
EG_PORT = 156

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
        else:
            data.append(gc.DataTuple(k, v))

    data_tuple = table_info.make_data(data, action_name)

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

bfrt_info = self.interface.bfrt_info_get("p4_mat_tests")
interface.bind_pipeline_config(p4_name=bfrt_info.p4_name)

#
key = {
        'ig_intr_md.ingress_port': IG_PORT,
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_1', data_action, key, data)
#

#
key = {
        'hdr.ethernet.dstAddr': mac_str_to_int("ff:ff:ff:ff:ff:ff")
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_2', data_action, key, data)
#

#
key = {
        'hdr.ethernet.srcAddr': mac_str_to_int("02:00:00:00:00:01")
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_3', data_action, key, data)
#

#
key = {
        'hdr.ethernet.etherType': 0x0800
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_4', data_action, key, data)
#

#
key = {
        'hdr.ipv4.protocol': 0x11
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_5', data_action, key, data)
#

#
key = {
        'hdr.ipv4.srcAddr': ip2int("10.64.13.28")
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_6', data_action, key, data)
#

#
key = {
        'hdr.ipv4.dstAddr': ip2int("10.71.33.131")
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_7', data_action, key, data)
#

#
key = {
        'hdr.udp.srcPort': 2152
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_8', data_action, key, data)
#

#
key = {
        'hdr.udp.dstPort': 2152
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_9', data_action, key, data)
#

#
key = {
        'hdr.gtp.teid': 1000
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_10', data_action, key, data)
#

#
key = {
        'hdr.ipv4_inner.srcAddr': ip2int("192.168.0.1")
      }
data = {
        'egress_port': EG_PORT
        }
data_action='a_to_cpu'
self.bfrt_connection.addEntry('table_11', data_action, key, data)
#
