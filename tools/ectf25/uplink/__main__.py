"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import asyncio

from ectf25.uplink import Channel, Uplink


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "secrets", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument(
        "host", 
        help="TCP hostname to serve on"
    )
    parser.add_argument(
        "port", 
        type=int, 
        help="TCP port to serve on"
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=Channel.from_parser,
        help="List of channel:fps:frames_file pairings "
        "(e.g., 1:10:channel1_frames.json 2:20:channel2_frames.json)",
    )
    args = parser.parse_args()

    await Uplink(args.secrets.read(), args.channels, args.host, args.port).serve()


asyncio.run(main())
