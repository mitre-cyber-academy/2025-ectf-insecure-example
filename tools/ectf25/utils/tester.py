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
import json
from pathlib import Path
import random
import string
import time
from typing import Iterator

from loguru import logger

from ectf25.utils import Encoder
from ectf25.utils.decoder import DecoderIntf


def rand_gen(args) -> Iterator[tuple[int, bytes, int]]:
    """Generate frames with random content for specified channels

    Generate --num-frames if provided, otherwise generate forever
    """
    idx = 0
    while args.num_frames < 0 or idx < args.num_frames:
        idx += 1

        # pick a random channel
        channel: int = random.choice(args.channels)

        # generate a random frame
        if args.ascii:
            frame = "".join(
                random.choices(string.printable, k=args.frame_size)
            ).encode()
        else:
            frame = random.randbytes(args.frame_size)

        # use the time for a timestamp
        timestamp = time.time_ns() // 1000
        yield channel, frame, timestamp


def stdin_gen(_) -> Iterator[tuple[int, bytes, int]]:
    """Read newline separated frames from stdin

    Input should be in format of 'channel(int),frame(str),timestamp(int)'
    """
    # get frames from stdin forever
    while True:
        # get frame
        raw_in = input().strip()
        try:
            # try to split comma-separated frame into components
            channel, frame, timestamp = raw_in.split(",")
            # yield values for main testing loop
            yield int(channel, 0), frame.encode(), int(timestamp, 0)
        except ValueError:
            logger.warning(
                "Frame should be in format of 'channel(int),frame(str),timestamp(int)'."
                f" Got {repr(raw_in)}"
            )


def json_gen(args) -> Iterator[tuple[int, bytes, int]]:
    """Load frames from a JSON file

    JSON must be in structure of [[channel, frame, timestamp], ...]. See `frames/`
    """
    # load frames from JSON file
    frames = json.load(args.file)

    # ensure top structure is a list
    if not isinstance(frames, list):
        exit("Frames JSON must be in structure of [[channel, frame, timestamp], ...]")

    # loop forever if --loop argument was provided, otherwise just loop once
    first = True
    while first or args.loop:
        first = False

        # loop through frames in file
        for frame in frames:
            try:
                # try to unpack frame into components
                channel, data, timestamp = frame

                # use real timestamp if --real-ts arg was provided
                if args.real_ts:
                    timestamp = time.time_ns() // 1000

                # yield values to outer loop
                yield channel, data.encode(), timestamp
            except ValueError:
                logger.warning(
                    "Frame should be in format of '(channel, frame, timestamp)',"
                    f" got {frame}"
                )


def parse_args():
    """Parse the command line arguments

    For top-level arguments and help, run:
        python3 -m ectf25.dev.tester --help

    For generator-specific arguments, run (picking one of stdin, rand, or json):
        python3 -m ectf25.dev.tester {stdin,rand,json} --help
    """
    parser = argparse.ArgumentParser(prog="ectf25.dev.tester")

    # top-level arguments
    parser.add_argument(
        "--secrets",
        "-s",
        type=argparse.FileType("rb"),
        required=True,
        help="Path to the secrets file",
    )
    parser.add_argument(
        "--port",
        "-p",
        default=None,
        help="Serial port to the Decoder (See https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)",
    )
    parser.add_argument(
        "--delay", "-d", type=float, default=0, help="Delay after frame decoding"
    )
    parser.add_argument("--perf", action="store_true", help="Display performance stats")
    parser.add_argument(
        "--stub-encoder",
        action="store_true",
        help="Stub out encoder and pass frames directly to decoder",
    )
    parser.add_argument(
        "--stub-decoder",
        action="store_true",
        help="Stub out decoder and print decoded frames",
    )
    parser.add_argument(
        "--dump-raw", type=Path, default=None, help="Dump raw frames to a file"
    )
    parser.add_argument(
        "--dump-encoded", type=Path, default=None, help="Dump encoded frames to a file"
    )
    parser.add_argument(
        "--dump-decoded", type=Path, default=None, help="Dump decoded frames to a file"
    )
    subparsers = parser.add_subparsers(required=True)

    # subparser for stdin frame generator (no arguments)
    parser_stdin = subparsers.add_parser("stdin", help="Read frames from stdin")
    parser_stdin.set_defaults(frame_generator=stdin_gen)

    # subparser and arguments for the random frame generator
    parser_rand = subparsers.add_parser("rand", help="Generate random frames")
    parser_rand.set_defaults(frame_generator=rand_gen)
    parser_rand.add_argument(
        "--ascii",
        "-a",
        action="store_true",
        help="Only use ASCII-printable characters for frames",
    )
    parser_rand.add_argument(
        "--num-frames",
        "-n",
        type=int,
        default=-1,
        help="Specific number of frames, otherwise generate forever",
    )
    parser_rand.add_argument(
        "--channels",
        "-c",
        nargs="+",
        type=int,
        default=[0, 1, 2, 3],
        help="Channels to randomly chose from (NOTE: 0 is broadcast)",
    )
    parser_rand.add_argument(
        "--frame-size", "-f", type=int, default=64, help="Size (in bytes) of frame"
    )

    # subparser and arguments for json frame generator
    parser_json = subparsers.add_parser(
        "json",
        help="Read frames from a json file like [[channel, frame, timestamp], ...]",
    )
    parser_json.set_defaults(frame_generator=json_gen)
    parser_json.add_argument("file", type=argparse.FileType("r"), help="Path to json")
    parser_json.add_argument(
        "--real-ts", action="store_true", help="Use live timestamps instead of input"
    )
    parser_json.add_argument(
        "--loop", action="store_true", help="Loop at end of json source"
    )
    args = parser.parse_args()

    if args.port is None and not args.stub_decoder:
        exit("--port must be provided if not using --stub-decoder")
    return args


def main():
    args = parse_args()

    # read secrets file

    encoder = Encoder(args.secrets.read())

    raw_frames = []
    encoded_frames = []
    decoded_frames = []
    decoder = DecoderIntf(args.port)

    # performance stats
    nbytes = 0
    encoder_time = 0
    decoder_time = 0

    try:
        # get frames from generator
        for channel, raw_frame, timestamp in args.frame_generator(args):
            logger.debug(f"RAW IN  C: {channel}, F: {raw_frame}, TS: {timestamp}")
            nbytes += len(raw_frame)
            raw_frames.append(
                (channel, raw_frame.decode(errors="backslashreplace"), timestamp)
            )

            # encode frame or use raw frame if encoder stubbed out
            if args.stub_encoder:
                encoded_frame = raw_frame
                logger.warning("Encoder stubbed out. Using raw frame")
            else:
                start = time.perf_counter()
                encoded_frame = encoder.encode(channel, raw_frame, timestamp)
                encoder_time += time.perf_counter() - start

            logger.debug(f"ENC OUT {repr(encoded_frame)}")
            encoded_frames.append(
                (channel, encoded_frame.decode(errors="backslashreplace"), timestamp)
            )

            # decode frame or use encoded frame if decoder stubbed out
            if args.stub_decoder:
                decoded_frame = encoded_frame
                logger.warning("Decoder stubbed out. Using encoded frame")
            else:
                start = time.perf_counter()
                decoded_frame = decoder.decode(encoded_frame)
                decoder_time += time.perf_counter() - start

            # warn if frame doesn't match
            if raw_frame != decoded_frame:
                logger.error(f"Decode frame {repr(raw_frame)} != {repr(decoded_frame)}")

            logger.info(f"DEC OUT {repr(decoded_frame)}")
            decoded_frames.append(
                (channel, decoded_frame.decode(errors="backslashreplace"), timestamp)
            )

            # print performance stats if requested
            if args.perf:
                encoder_avg = "N/A" if args.stub_encoder else int(nbytes / encoder_time)
                decoder_avg = "N/A" if args.stub_decoder else int(nbytes / decoder_time)
                logger.info(
                    f"STATS: encoder {encoder_avg} B/s, decoder {decoder_avg} B/s"
                )

            # sleep if requested
            time.sleep(args.delay)
    finally:
        # dump frames
        if args.dump_raw:
            with open(args.dump_raw, "w") as f:
                json.dump(raw_frames, f)
        if args.dump_encoded:
            with open(args.dump_encoded, "w") as f:
                json.dump(encoded_frames, f)
        if args.dump_decoded:
            with open(args.dump_decoded, "w") as f:
                json.dump(decoded_frames, f)


if __name__ == "__main__":
    main()
