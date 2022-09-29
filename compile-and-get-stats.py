#!/usr/bin/env python

import glob
import sys
import socket
import binascii
import os
import json
import ipaddress

COMPILE_COMMAND = "bf-p4c mat-tests.p4 --display-power-budget -g "
TCAM_FLAG = "-D TCAM "
SIZES = [1, 64, 128, 512, 1024, 2048, 4096]
SIZE_FLAG = "-D TBL_SIZE_"

for i in SIZES:
    command = COMPILE_COMMAND + SIZE_FLAG + str(i)
    print(command)
    # os.system(COMPILE_COMMAND + SIZE_FLAG )

    js  = json.loads("mat-tests.tofino/pipe/logs")
    print(js["total_power"])

