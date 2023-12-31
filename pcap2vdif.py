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
import ipaddress

# pcapkit imports
from pcapkit import extract, UDP, IPv4

# Dict for storing frames per source and dest IP. Needs to be referenced via 'global' keyword.
# TODO The pythonic way to deal with this would probably be to make a class.
collected_frames = {}


def main(argv: Sequence[str] | None = None) -> int:
    # Process commandline arguments
    parser = argparse.ArgumentParser(
        description="""
        Extracts UDP datagram payloads from a PCAP capture file.

        Each VDIF frame will be stored in a file named
        {pcapfilestem}_{src_ip}_{dst_ip}_{packet#}.vdif, unless the --single-vdif argument is used.
        In that case, all VDIF frames identified for a src_ip/dst_ip pair will be stored in a single
        file using the same naming convention but without the {packet#} component.
        """,
        epilog=f"""This script is called {PurePath(__file__).stem} because it's assumed this will
            be used on PCAP captures that contain VDIF data frames inside UDP datagrams.""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('pcapfile',
        help='The PCAP file from which to extract VDIF data frames')
    parser.add_argument('-r', required=False, default=False, action='store_true',
        help='Disable IPv4 reassembly')
    parser.add_argument('--start-packet', required=False, default=0,
        help='PCAP packet number (0-based) from which to start extraction')
    parser.add_argument('--num-packets', required=False, default=0,
        help='Number of PCAP packets to extract (0=all packets from start packet)')
    parser.add_argument('--single-vdif', required=False, default=False, action='store_true',
        help='Stores all VDIF frames in a single VDIF file instead of individual files')
    args = parser.parse_args(argv)

    # Setup stuff for naming the output files
    vdif_outfile_stem = PurePath(args.pcapfile).stem

    # Extract selected packets and attempt IPv4 reassembly
    start_packet = int(args.start_packet)
    num_packets = int(args.num_packets)
    all_packets = (start_packet == 0) and (num_packets == 0)
    end_packet = 0 if num_packets == 0 else start_packet + num_packets
    extraction = extract(fin=args.pcapfile, nofile=True, store=True,
                        reassembly=not args.r, reasm_strict=True, ipv4=True, auto=all_packets)

    if not all_packets:
        # Read all packets up to the end. Necessary due to the PCAP format.
        for frame_no, e in enumerate(extraction):
            if frame_no == end_packet:
                break

    # Inspect the reassembled IPv4 packets if we got them
    if (not args.r) and (len(extraction.reassembly.ipv4) > 0):
        for dgram_no, dgram in enumerate(extraction.reassembly.ipv4):
            if UDP in dgram.packet:
                src = dgram.id.src
                dst = dgram.id.dst
                process_packet(
                    dgram.id.src, dgram.id.dst, dgram.packet.payload.data, vdif_outfile_stem,
                    not args.single_vdif, dgram_no
                )
    else:
        # pcapkit didn't reassemble IPv4 from the capture, so ... ¯\_(ツ)_/¯
        for frame_no, frame in enumerate(extraction.frame):
            if all_packets or (frame_no in range(start_packet, end_packet)):
                if frame.protocol == 'NULL':
                    # The frame is from a loopback interface and so we assume it's a full UDP
                    # datagram. We assume a 4-byte link layer header, 20-byte IP header, and 8-byte
                    # UDP header.
                    src = ipaddress.ip_address(frame.payload.data[4+12:4+16])
                    dst = ipaddress.ip_address(frame.payload.data[4+16:4+20])
                    process_packet(
                        src, dst, frame.payload.data[4+20+8:], vdif_outfile_stem,
                        not args.single_vdif, frame_no
                    )
                elif (frame.protocol == 'Ethernet') and (UDP in frame):
                    # This is an Ethernet frame that pcapkit could decode and no reassembly was
                    # required. We can look for UDP directly.
                    src = frame[IPv4].src
                    dst = frame[IPv4].dst
                    process_packet(
                        src, dst, frame[UDP].payload.data, vdif_outfile_stem, not args.single_vdif,
                        frame_no
                    )
                else:
                    pass

    if args.single_vdif:
        # Output all frames for each src/dst pair in a single VDIF file.
        global collected_frames

        for src in collected_frames:
            for dst in collected_frames[src]:
                if len(collected_frames[src][dst]) > 0:
                    write_vdif_file(collected_frames[src][dst], f'{vdif_outfile_stem}_{src}_{dst}')

    return 0


def process_packet(
    src: ipaddress.IPv4Address,
    dst: ipaddress.IPv4Address,
    vdif_frame: bytearray,
    vdif_outfile_stem: str,
    file_per_frame: bool = False,
    packet_no=None
) -> None:
    """Utility function for common handling of packet data."""
    global collected_frames

    if src not in collected_frames:
        # Add a new entry if we haven't seen this src yet.
        collected_frames[src] = {}
        collected_frames[src][dst] = bytearray()

    # Append the VDIF frame for the src/dst pair.
    collected_frames[src][dst] += vdif_frame

    if file_per_frame:
        # Write out the file for this VDIF frame
        write_vdif_file(
            collected_frames[src][dst], f'{vdif_outfile_stem}_{src}_{dst}', packet_no)


def write_vdif_file(vdif_frames, file_stem, frame_no=None):
    """Utility function for writing a VDIF file."""
    outfile = f'{file_stem}'
    if None is not frame_no:
        outfile += f'_{frame_no}'
    outfile += '.vdif'

    with open(outfile, 'wb') as of:
        of.write(vdif_frames)


if __name__ == "__main__":
    raise SystemExit(main())
