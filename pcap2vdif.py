#!/usr/bin/env python3
"""
Copyright (c) 2023 Center for Astrophysics | Harvard & Smithsonian

This software is licensed for use as described in the LICENSE file in
the root directory of this distribution.

Originator: Ryan Chaves 24 Aug 2023
"""
from __future__ import annotations

# Standard imports
import argparse
from collections.abc import Sequence
from pathlib import PurePath

# pcapkit imports
from pcapkit import extract, UDP


def main(argv: Sequence[str] | None = None) -> int:
    # Process commandline arguments
    parser = argparse.ArgumentParser(
        description="""Extracts UDP datagram payloads from a PCAP capture file.""",
        epilog=f"""This script is called {PurePath(__file__).stem} because it's assumed this will
            be used on PCAP captures that contain VDIF data frames inside UDP datagrams.""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--pcapfile', required=False,
        help='The PCAP file from which to extract VDIF data frames')
    parser.add_argument('-r', required=False, default=False, action='store_true',
        help='Disable IPv4 reassembly')
    parser.add_argument('--start-packet', required=False, default=0,
        help='PCAP packet number (0-based) from which to start extraction')
    parser.add_argument('--num-packets', required=False, default=0,
        help='Number of PCAP packets to extract (0=all packets from start packet)')
    args = parser.parse_args(argv)

    # Setup stuff for naming the output files
    vdif_outfile_stem = PurePath(args.pcapfile).stem

    # Extract selected packets and attempt IPv4 reassembly
    all_packets = (args.start_packet == 0) and (args.num_packets == 0)
    extraction = extract(fin=args.pcapfile, nofile=True, store=True,
                        reassembly=not args.r, reasm_strict=True, ipv4=True, auto=all_packets)

    if not all_packets:
        # Read all packets up to the end. Necessary due to the PCAP format.
        end_packet = 0 if args.num_packets == 0 else args.start_packet + args.num_packets
        for frame_no, e in enumerate(extraction):
            if frame_no == end_packet:
                break

    # Inspect the reassembled IPv4 packets if we got them
    if (not args.r) and (len(extraction.reassembly.ipv4) > 0):
        for dgram_no, dgram in enumerate(extraction.reassembly.ipv4):
            if UDP in dgram.packet:
                write_vdif_file(dgram.packet.payload.data, vdif_outfile_stem, frame_no)
    else:
        # pcapkit didn't reassemble IPv4 from the capture, so ... ¯\_(ツ)_/¯
        for frame_no, frame in enumerate(extraction.frame):
            if frame_no in range(args.start_packet, end_packet):
                if frame.protocol == 'NULL':
                    # The frame is from a loopback interface and so we assume it's a full UDP
                    # datagram. We assume a 4-byte link layer header, 20-byte IP header, and 8-byte
                    # UDP header.
                    write_vdif_file(frame.payload.data[4+20+8:], vdif_outfile_stem, frame_no)
                elif (frame.protocol == 'Ethernet') and (UDP in frame):
                    # This is an Ethernet frame that pcapkit could decode and no reassembly was
                    # required. We can look for UDP directly.
                    write_vdif_file(frame[UDP].payload.data, vdif_outfile_stem, frame_no)
                else:
                    pass

    return 0


def write_vdif_file(vdif_frame, file_stem, frame_no):
    outfile = f'{file_stem}_{frame_no}.vdif'
    with open(outfile, 'wb') as of:
        of.write(vdif_frame)


if __name__ == "__main__":
    raise SystemExit(main())
