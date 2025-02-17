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
import serial

from loguru import logger
from tqdm import trange


class BootloaderIntf:
    """Standard bootloader interface

    See https://rules.ectf.mitre.org/2025/getting_started/boot_reference
    """

    PAGE_SIZE = 8192
    APP_PAGES = 28
    TOTAL_SIZE = APP_PAGES * PAGE_SIZE

    COMPLETE_CODE = 20
    SUCCESS_CODES = {1, 2, 3, 4, 5, 7, 8, 10, 11, 13, 16, 18, 19, COMPLETE_CODE}
    ERROR_CODES = {6, 9, 12, 14, 15, 17}

    UPDATE_COMMAND = b"\x00"
    BLOCK_SIZE = 16

    def __init__(self, port: str, **serial_kwargs):
        """
        :param port: Serial port to the board
        :param serial_kwargs: Args to pass to the serial interface construction
        """
        # Open serial port
        self.ser = serial.Serial(port=port, baudrate=115200, **serial_kwargs)
        self.ser.reset_input_buffer()

    # Wait for expected bootloader response byte
    # Exit if response does not match
    def _verify_resp(self) -> int:
        """Get and check the response code"""
        while (resp := self.ser.read(1)) == b"":
            pass
        resp = ord(resp)
        if resp in self.ERROR_CODES:
            logger.error(f"Bootloader responded with: {resp}")
            exit(-1)
        if resp not in self.SUCCESS_CODES:
            logger.error(f"Unexpected bootloader response: {resp}")
            exit(-2)
        return resp

    def update(self, image: bytes):
        """Update the board with an image

        :param image: Raw image to be programmed to the board
        """
        # Pad image
        image = image + (b"\xff" * (self.TOTAL_SIZE - len(image)))

        # Send update command
        logger.info("Requesting update")
        self.ser.write(b"\x00")

        self._verify_resp()
        self._verify_resp()

        # Send image and verify each block
        logger.info("Update started")
        logger.info("Sending image data...")
        for idx in trange(0, len(image), self.BLOCK_SIZE):
            self.ser.write(image[idx : idx + self.BLOCK_SIZE])
            self._verify_resp()

        logger.info("Listening for installation status...\n")

        # Wait for update finish
        while self._verify_resp() != self.COMPLETE_CODE:
            pass

        logger.success("Update Complete!\n")

        self.ser.close()


def main():
    parser = argparse.ArgumentParser(prog="ectf25.utils.flash")
    parser.add_argument(
        "infile", type=argparse.FileType("rb"), help="Path to the input binary"
    )
    parser.add_argument("port", help="Serial port")
    args = parser.parse_args()

    image = args.infile.read()
    BootloaderIntf(args.port).update(image)


if __name__ == "__main__":
    main()
