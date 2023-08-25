#!/usr/bin/env python3
"""
Copyright (c) 2023 Center for Astrophysics | Harvard & Smithsonian

This software is licensed for use as described in the LICENSE file in
the root directory of this distribution.

Originator: Ryan Chaves 24 Aug 2023
"""
# Standard imports
import argparse
from collections.abc import Sequence
import logging
import socket
import os

# baseband imports
import baseband.vdif as vdif


def main(argv: Sequence[str] | None = None) -> int:
    # Process commandline arguments
    parser = argparse.ArgumentParser(
        description="""Pretends to be a VLBI digital back end (DBE) by extracting VDIF data frames
             from a file and sending them as UDP datagrams to a host.""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-v', '--verbose', required=False, action='store_true',
        help='Print some extra info during runtime')
    parser.add_argument('-i', '--ip', '--host', required=False,
        default='localhost',
        help='The host or IP to which to send UDP datagrams',
    )
    parser.add_argument('-p', '--port', required=False, default=7890,
        help='The port on which to send UDP datagrams',
    )
    parser.add_argument('vdif_file', help='The VDIF file to stream')
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        logging.info(f"Arguments were {vars(args)}")

    with vdif.open(args.vdif_file, 'rb') as fh:
        # Get a structured version of the VDIF data frames
        fs = fh.read_frameset()

        # Now go back to the beginning of the file for easy raw transmission
        fh.seek(0, os.SEEK_SET)

        # Setup the UDP sender
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Send each VDIF Frame
        for f in fs.frames:
            content = fh.read(f.header.frame_nbytes)
            sock.sendto(content, (args.ip, args.port))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
