#!/usr/bin/env python3
"""
FLARE P4Runtime Controller
===========================
- Connects to BMv2 simple_switch_grpc
- Installs the compiled pipeline (p4info + bmv2.json)
- Adds example flow rules (here: table entries)
- Reads counters from stateful registers (RST, FIN, FRAG)
"""

import sys
import grpc
import time
import threading

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper

# Paths to our config files
P4INFO_FILE_PATH = "configs/p4info.txt"
BMV2_JSON_FILE_PATH = "configs/bmv2.json"

# Switch gRPC endpoint
SWITCH_ADDRESS = '127.0.0.1:50051'
DEVICE_ID = 0


def write_table_entry(p4info_helper, sw):
    """
    Insert an example table entry to match TCP flags.
    For demonstration: match TCP RST flag == 1
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.check_tcp_flags",
        match_fields={
            "hdr.tcp.flags": (0x04, 0xff)  # match RST flag
        },
        action_name="MyIngress.count_rst",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)
    print("Installed example RST flag match rule.")


def read_register(p4info_helper, sw, register_name):
    """
    Reads and prints all register entries for the given register.
    """
    for response in sw.ReadRegisters(p4info_helper.get_register_id(register_name)):
        for entity in response.entities:
            reg_entry = entity.register_entry
            index = reg_entry.index.index
            data = reg_entry.data.bitstring
            print(f"Register {register_name}[{index}] = {int(data, 2)}")


def main():
    p4info_helper = P4InfoHelper(P4INFO_FILE_PATH)

    try:
        # Establish gRPC connection
        sw = p4info_helper.connect(
            name='flare_sffp_switch',
            address=SWITCH_ADDRESS,
            device_id=DEVICE_ID,
            proto_dump_file='logs/grpc_dump.txt'
        )

        # Install pipeline config
        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=BMV2_JSON_FILE_PATH)
        print("Installed P4 pipeline successfully!")

        # Insert example entry
        write_table_entry(p4info_helper, sw)

        # Loop to read register values every 10s
        while True:
            print("\n=== Reading RST Counts ===")
            read_register(p4info_helper, sw, "MyIngress.rst_count")

            print("\n=== Reading FIN Counts ===")
            read_register(p4info_helper, sw, "MyIngress.fin_count")

            print("\n=== Reading Fragment Counts ===")
            read_register(p4info_helper, sw, "MyIngress.frag_count")

            time.sleep(10)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print(f"gRPC failed: {e}")

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    main()
