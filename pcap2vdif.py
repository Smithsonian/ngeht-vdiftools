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
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapfile',
        help='The PCAP file from which to extract VDIF data frames')
    args = parser.parse_args(argv)

    # Setup stuff for naming the output files
    vdif_outfile_stem = PurePath(args.pcapfile).stem

    # Extract all frames and attempt IPv4 reassembly
    extraction = extract(fin=args.pcapfile, nofile=True, store=True,
                         reassembly=True, reasm_strict=True, ipv4=True)

    # Inspect the reassembled IPv4 packets if we got them
    if len(extraction.reassembly.ipv4) > 0:
        for dgram_no, dgram in enumerate(extraction.reassembly.ipv4):
            if UDP in dgram.packet:
                # TODO Should we check anything else?
                vdif_frame = dgram.packet.payload.data
                outfile = f'{vdif_outfile_stem}_{dgram_no}.vdif'
                with open(outfile, 'wb') as of:
                    of.write(vdif_frame)
    else:
        # pcapkit didn't reassemble IPv4 from the capture, so ... ¯\_(ツ)_/¯
        for frame_no, frame in enumerate(extraction.frame):
            if frame.protocol == 'NULL':
                # The frame is from a loopback interface and so we assume it's a full UDP datagram.
                # We assume a 4-byte link layer header, 20-byte IP header, and 8-byte UDP header.
                vdif_frame = frame.payload.data[4+20+8:]
                outfile = f'{vdif_outfile_stem}_{frame_no}.vdif'
                with open(outfile, 'wb') as of:
                    of.write(vdif_frame)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())