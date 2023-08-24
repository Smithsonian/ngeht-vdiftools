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
    frame_no = 0

    # Extract all UDP datagrams
    extraction = extract(fin=args.pcapfile, nofile=True, protocol=UDP)
    for frame in extraction.frame:
        if UDP in frame:
            # TODO Should we check anything else?
            vdif_frame = frame[UDP].payload.data
            outfile = f'{vdif_outfile_stem}_{frame_no}.vdif'
            with open(outfile, 'wb') as of:
                of.write(vdif_frame)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())