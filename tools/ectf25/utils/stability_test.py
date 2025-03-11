"""
Author: Sam Meyers
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import time
import random
import string
import argparse
import psutil
from psutil import Process

from loguru import logger

from ectf25.utils.decoder import DecoderIntf, DecoderError
from ectf25_design.encoder import Encoder
from ectf25_design.gen_subscription import gen_subscription


ROLLING_TIME_SECONDS = 5

FPS_REQ_ENCODER = 1000
FPS_REQ_DECODER = 10

FRAME_SIZE = 64

ENC_TEST_SIZE = 1000
DEC_TEST_SIZE = 10

MS_PER_SEC = 1000

DEC_FRAME_MS = 150


class TimingError(RuntimeError):
    pass


# A function decorator that throws an exception if a test fails to execute in a predetermined time.
# This does not enforce that the function will return in the specified amount of time. It should be
# used for tests that are more or less guaranteed to complete.
def timed_call(max_runtime_ms: int = MS_PER_SEC, enforce_time: bool = True):
    def decorator(func):
        def wrapper(*args, **kwargs) -> tuple[type, float]:
            """
            This decorator enables executing a test with a max execution time. If the max execution
            time is exceeded and `enforce_time` is True, the decorator throws a TimingError.

            returns: the execution time in seconds of the test and the return value as a tuple
            """
            # The order in which we record start and end times matters. We will put the start and
            # end on the bookends of the measurement. This ensures that start and end *should*
            # be larger than the other time measurements, so we should avoid negative test times.
            start = time.perf_counter()
            process_start = Process().cpu_times().user
            user_start = psutil.cpu_times().user / psutil.cpu_count()

            ret = func(*args, **kwargs)

            user_end = psutil.cpu_times().user / psutil.cpu_count()
            # Process() is an object that represents the current state. We must reinstantiate this
            # object for the 2nd measurement
            process_end = Process().cpu_times().user
            end = time.perf_counter()

            # Calculate `runtime = ΔrealTime - ((ΔOSCPUTime / numCPUs) - ΔProcessCPUTime)`. The idea
            # is to account for unfortunate process scheduling or a busy CPU. This isn't a perfectly
            # accurate solution, but it's better than relying on real time only. Ignore kernel time
            # for now because it seems negligible.
            runtime_ms = (
                (end - start)
                - ((user_end - user_start) - (process_end - process_start))
            ) * MS_PER_SEC

            # Symptom of measurement inaccuracies. Occasionally with the reference encoder, process
            # time is reported as 0. This makes a test that took "negative" time. Obviously this is
            # impossible, so we account for this case here. If the duration is "negative," then in
            # actuality it was quite fast. Therefore, while this isn't a correct solution, it will
            # prevent false negatives and will most likely not cause false positives. I don't expect
            # this case will be hit at all on designs that implement more crypto overhead than the
            # reference.
            if runtime_ms < 0:
                runtime_ms = 0.01

            if runtime_ms > max_runtime_ms and enforce_time:
                raise TimingError(
                    f"{func.__name__} failed to execute in {max_runtime_ms} ms! Took {runtime_ms}"
                )
            else:
                return runtime_ms / MS_PER_SEC, ret

        return wrapper

    return decorator


def random_frame(length: int) -> bytes:
    """
    Generate a frame with random printable content
    """
    # Not the most interesting TV to watch, but it gets the job done
    return "".join(random.choice(string.printable) for _ in range(length)).encode()


class StabilityTester:
    """
    Test the stability of a design. The intent is to perform a long-running test of the decoder to
    ensure that it meets functional timing requirements under extended usage. Default test length
    is 8 hours.
    """

    def __init__(
        self,
        decoder_port: str,
        global_secrets: bytes,
        device_id: int,
        results_file: str,
        duration_minutes: int = 480,
        channel: int = 1,
        should_subscribe: bool = False,
    ):
        self.decoder_port = decoder_port
        self.global_secrets = global_secrets
        self.device_id = device_id
        self.results_file = results_file
        self.duration_minutes = duration_minutes
        self.channel = channel

        self.decoder_intf = DecoderIntf(decoder_port)
        self.encoder = Encoder(global_secrets)

        self.timestamp = 0

        self.total_decodes = 0
        self.timing_fails = 0

        if should_subscribe:
            self._subscribe()

    def _subscribe(self):
        ts_min = 0
        ts_max = 0xFFFF_FFFF_FFFF_FFFF
        # these will throw their own errors, no need to check return values
        sub = gen_subscription(
            self.global_secrets, self.device_id, ts_min, ts_max, self.channel
        )
        self.decoder_intf.subscribe(sub)

    @timed_call(max_runtime_ms=DEC_FRAME_MS, enforce_time=True)
    def decode_frame(self, frame: bytes) -> tuple[float, bytes]:
        """
        Decode one frame
        """
        return self.decoder_intf.decode(frame)

    def encode_frame(self, ptxt_frame: bytes, timestamp: int):
        """
        Encode one frame
        """
        return self.encoder.encode(self.channel, ptxt_frame, timestamp)

    # We use enforce_time=False here because we enforce FPS as a rolling 5-second average.
    # If any given second fails the FPS requirement, that's fine, provided it passes the 5
    # second avg.
    @timed_call(enforce_time=False)
    def encode(self, frames: list[bytes]) -> list[bytes]:
        """
        Encode a set of frames
        """
        ret = []
        for frame in frames:
            self.timestamp += random.randint(1, 255)
            frame = self.encode_frame(frame, self.timestamp)
            ret.append(frame)
        return ret

    @timed_call(enforce_time=False)
    def decode(self, frames: list[bytes]) -> list[bytes]:
        """
        Decode a set of frames
        """
        ret = []
        for frame in frames:
            self.total_decodes += 1
            try:
                _, frame = self.decode_frame(frame)
            except TimingError:
                self.timing_fails += 1
                frame = None
            ret.append(frame)
        return ret

    def run(self):
        """
        Run the stability test

        If the function returns, the test was successful. If a TimingError or DecoderError are
        raised, the test failed.
        """
        enc_times = []
        dec_times = []

        start = time.time()
        while time.time() - start < self.duration_minutes * 60:
            ptxt_frames = []

            for _ in range(ENC_TEST_SIZE):
                ptxt_frames.append(random_frame(FRAME_SIZE))

            enc_time, enc_frames = self.encode(ptxt_frames)
            enc_times.append(enc_time)

            # Trim down the generated list for the decode test, as Encoder FPS
            # requirement is higher than Decoder
            subset = set(random.sample(range(ENC_TEST_SIZE), DEC_TEST_SIZE))
            enc_frames = [f for idx, f in enumerate(enc_frames) if idx in subset]

            dec_time, dec_frames = self.decode(enc_frames)
            dec_times.append(dec_time)

            # ensure each frame plaintext matches
            for idx, frame in zip(sorted(subset), dec_frames):
                # If frame is None, we failed the 150 ms req, skip the check
                if frame is not None and frame != ptxt_frames[idx]:
                    raise DecoderError(f"{frame} != {ptxt_frames[idx]}")

            # check encoder meets FPS requirement
            if len(enc_times) >= ROLLING_TIME_SECONDS:
                enc_fps = (len(enc_times) * ENC_TEST_SIZE) / sum(enc_times)
                logger.debug(f"Current Encoder FPS: {enc_fps}")
                if enc_fps < FPS_REQ_ENCODER:
                    raise TimingError(
                        f"Rolling encoder FPS requirement not met. Current FPS: {enc_fps}"
                    )
                # if we are at the 5 second mark for enc, remove the first entry
                enc_times.pop(0)

            # check decoder meets FPS requirement
            if len(dec_times) >= ROLLING_TIME_SECONDS:
                dec_fps = (len(dec_times) * DEC_TEST_SIZE) / sum(dec_times)
                logger.debug(f"Current Decoder FPS: {dec_fps}")
                if dec_fps < FPS_REQ_DECODER:
                    raise TimingError(
                        f"Rolling decoder FPS requirement not met. Current FPS: {dec_fps}"
                    )
                # if we are at the 5 second mark for dec, remove the first entry
                dec_times.pop(0)

        results_fmt = f"Timing fails: {self.timing_fails}\n"
        results_fmt += f"Total decodes: {self.total_decodes}\n"
        results_fmt += f"Failure rate: {self.timing_fails / self.total_decodes}\n"
        logger.info(results_fmt)
        if self.results_file is not None:
            with open(self.results_file, "w") as f:
                f.write(results_fmt)
        return self.timing_fails


def parse_args():
    parser = argparse.ArgumentParser(prog="stability_test.py")
    parser.add_argument(
        "-p", "--port", required=True, type=str, help="Decoder serial port"
    )
    parser.add_argument(
        "-g", "--global-secrets", required=True, type=str, help="Path to global secrets"
    )
    parser.add_argument(
        "-c", "--channel", required=True, type=int, help="Channel to test on"
    )
    parser.add_argument(
        "-di",
        "--decoder-id",
        required=True,
        type=lambda x: int(x, 16),
        help="Decoder ID",
    )
    parser.add_argument(
        "-r",
        "--results-file",
        type=str,
        default=None,
        help="File where results will be stored",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=480,  # 480 minutes = 8 hours
        help="Duration of the test in minutes",
    )
    parser.add_argument(
        "-s",
        "--subscribe",
        action="store_true",
        default=False,
        help="Provide a subscription",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.global_secrets, "rb") as f:
        global_secrets = f.read()

    st = StabilityTester(
        args.port,
        global_secrets,
        args.decoder_id,
        args.results_file,
        args.duration,
        args.channel,
        args.subscribe,
    )
    st.run()


if __name__ == "__main__":
    main()
