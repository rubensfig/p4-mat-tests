#!/usr/bin/env python

import os
import json
import pandas as pd

COMPILE_COMMAND = "bf-p4c --display-power-budget -g "
TCAM_FLAG = " -D TCAM "
TBL_SIZES = [1, 64, 128, 512, 1024, 2048, 4096]
WDTH_SIZES = [32, 64, 128, 512]
SIZE_FLAG = " -D TBL_SIZE_"
WDTH_FLAG = " -D WDTH_"
TABLES = [2,3,4,5,6,7,8,9,10]
K_WDTH_SIZES = [9, 25, 41, 73, 105, 153, 201]
TBL_FLAG = " -D TBL_"
K_WDTH_FLAG = " -D SZ_"
PROGRAM = " mat-tests-sram-key.p4"

pwr_df = pd.DataFrame(columns=["table_size", "type", "gress", "power"])
for i in K_WDTH_SIZES:
    command = COMPILE_COMMAND + K_DWDTH_FLAG + str(i) + PROGRAM
    print(command)
    os.system(command)

    data = None
    with open("mat-tests-sram-key.tofino/pipe/logs/power.json") as f:
        data = json.load(f)
    print(data["total_power"])

    tp = "sram" if TCAM_FLAG not in command else "tcam"
    #df_tmp = pd.DataFrame([i, tp, data["total_power"][0]["gress"], data["total_power"][0]["power"]], columns = {"table_size", "type", "gress", "power"})
    pwr_df = pwr_df.append(
            pd.Series(
                [i, tp, data["total_power"][0]["gress"], data["total_power"][0]["power"]],
                index = pwr_df.columns),
                ignore_index=True
    )
     
pwr_df.to_csv("power_table_size_sram_key.csv")
