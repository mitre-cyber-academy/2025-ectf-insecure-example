"""
Author: Crypto Caballeros
Date: 2025

This file is used to generate secrets for a deployement of a satellite TV system.
"""

import argparse
import json
from pathlib import Path
import os

from loguru import logger


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """
    # Secrets stored in JSON files cannot be stored as binary values, 
    # they must be encoded to hex, base64, or another type of ASCII-only encoding

    # Key created for encrypting frames in encoder;
    # random 32 byte value is converted to hex (64 digits)
    encryption_key = os.urandom(32).hex()

    # Key created for subscription signing or other subscription securing work;
    # random 32 byte value is converted to hex (64 digits)
    subscription_key = os.urandom(32).hex()

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers
    secrets = {
        "channels": channels,
        "encryption_Key": encryption_key,
        "subscription_Key": subscription_key,
    }

    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
