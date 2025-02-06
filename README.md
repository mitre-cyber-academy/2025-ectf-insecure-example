# eCTF Insecure Example

This repository holds the insecure example design for an eCTF Satellite TV System.

## Layout

- `decoder/` - Firmware for the television decoder.
    - `project.mk` - This file defines project specific variables included in the Makefile
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a decoder.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `wolfssl/` - Location to place wolfssl library for included Crypto Example
- `design/` - Host design elements
    - `ectf25_design/` - Host design source code
        - `encoder.py` - Encodes frames
        - `gen_secrets.py` - Generates shared secrets
        - `gen_subscription.py` - Generates subscription updates
    - `pyproject.toml` - File that tells pip how to install this module
- `frames/` - Example frame data
- `tools/` - Host tools - DO NOT MODIFY ANYTHING IN THIS DIRECTORY
    - `ectf25/` - Directory with tool source
        - `tv/` - Sends received frames to the decoder
            - `list.py` - Tool to list active decoder subscriptions
            - `subscribe.py` - Tool to update decoder subscriptions
        - `uplink/` - Encodes frames and sends them to satellite
        - `utils/` - Host tool utilities
            - `decoder.py` - Interface with decoder hardware/firmware. This file should not be directly executed.
            - `flash.py` - Firmware update utility
            - `stress_test.py` - Utility for testing decoder
            - `tester.py` - Utility for testing decoder
        - `satellite.py` - Broadcasts frames from uplink to all decoders
    - `pyproject.toml` - File that tells pip how to install this module

## Usage and Requirements

This repository contains three main elements: firmware source code, host design elements, and tooling.

Firmware is built through using the Docker environments for each component as
described below. Be sure to have Docker running while executing docker commands.

Source code and tooling is provided that runs directly on the host. All of
these tools are created in Python. Note that all example tool invocations
are written for a Unix based OS. Users running these tools on windows may need
to change some details of the command for their own machine (e.g. '`python` -> `py`',
'`path/to/file`' -> '`path\to\file`', '`-v ./path/to/volume:/dest`' ->
'`-v .\path\to\volume:/dest`', '`/dev/tty.usbmodem123`' -> '`COM12`').

**Note:** Command listed under any "Example Utilization" section should be executed from the root directory of this repository.

### Environment Build

The environment is built with Docker, which should install all necessary packages for running the
design in a reproducible fashion.

When building for the first time, this may take some time (10+ minutes) to
complete. Furthermore, it is recommended that you use a wired internet
connection when building for the first time.

### Host Tools

Host Tools includes everything in the `tools` directory. These do not need to be modified by teams
except for local testing. Your design should work with the standardized
interface between host and Decoder hardware. The host tools will pass any
required arguments to the Decoder hardware and process all relevant output.

### Decoder

When building the decoder, the `Makefile` in the decoder directory will be
invoked by the Docker run command.

## Using the eCTF Tools

In order to run the eCTF Tools, you must first ensure that you have installed
all of the required packages (ideally into a virtual environment). You can
install packages from the included `pyproject.toml` file in the root of the
design and tools directories. This file should not be modified.

### Linux:

```bash
# Create a virtual environment in the root of the design
cd <example_root>
python -m venv .venv --prompt ectf-example

# Enable virtual environment
. ./.venv/bin/activate

# Install the host tools
python -m pip install ./tools/

# Install the host design elements as an editable module
python -m pip install -e ./design/
```

### PowerShell:

```
#Create a virtual environment in the root of the design
cd .\<example_root>
python -m venv .venv --prompt ectf-example

#Enable virtual environment 
. .\.venv\Scripts\Activate.ps1

#Install the host tools
python -m pip install .\tools\

#Install the host design design elements as an editable module 
python -m pip install -e .\design\

```

### Building the deployment

Optionally, shared secrets used by the decoder and encoder can be generated. A directory containing shared secrets
should be
mounted as a volume to the decoder docker image. This directory should be somewhere accessible to the decoder, host
tools, and
host design elements.

This will generate a secrets file for channels 1, 3, and 4.

```bash
mkdir secrets
python -m ectf25_design.gen_secrets secrets/secrets.json 1 3 4
```

### Building the Decoder

The Decoder can be built next. The generated secrets will be available in the docker container at `/root/secrets/`.

These commands will generate a Decoder build with a Device ID 0xdeadbeef. Build outputs are copied to the `build_out`
directory.

### Linux:

```bash
cd <example_root>/decoder
docker build -t decoder .
docker run --rm -v ./build_out:/out -v ./:/decoder -v ./../secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
```

### PowerShell:

```
cd <example_root>\decoder 
docker build -t decoder .
docker run --rm -v .\build_out:/out -v .\:/decoder -v .\..\secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
```

#### Note: If the build is hanging indefinitely, try restarting Docker. If that does not resolve the issue, a system restart should fix the issue.

## Generating Subscription Updates

Subscription updates are generated using the `gen_subscription.py` script.
The `gen_subscription` function will be the only feature that teams will need to update.

```
python -m ectf25_design.gen_subscription -h
usage: gen_subscription.py [-h] [--force] secrets_file subscription_file device_id start end channel

positional arguments:
  secrets_file       Path to the secrets file created by ectf25_design.gen_secrets
  subscription_file  Subscription output
  device_id          Device ID of the update recipient.
  start              Subscription start timestamp
  end                Subscription end timestamp
  channel            Channel to subscribe to

options:
  -h, --help         show this help message and exit
  --force, -f        Force creation of subscription file, overwriting existing file
```

### **Example Utilization**

This command will create a subscription file called subscription.bin targeting a device with ID 0xDEADBEEF, a start
timestamp of 32, and an end timestamp of 128 for channel 1.

#### Linux and PowerShell

```bash
python -m ectf25_design.gen_subscription secrets/secrets.json subscription.bin 0xDEADBEEF 32 128 1
```

## Flashing

Flashing the MAX78000 is done through the eCTF Bootloader. You will need to initially flash
the eCTF Bootloader onto the provided hardware. The device must be in update mode in order for
these commands to execute (flashing blue LED).

```
python -m ectf25.utils.flash -h
usage: ectf25.utils.flash [-h] infile port

positional arguments:
  infile      Path to the input binary
  port        Serial port

options:
  -h, --help  show this help message and exit
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.utils.flash ./decoder/build_out/max78000.bin /dev/tty.usbmodem11302
```

#### PowerShell

```
python -m ectf25.utils.flash .\decoder\build_out\max78000.bin COM12
```

## Host Tools

### List Tool

The list tool applies the required list channels functionality from the Satellite TV Decoder system.

```
python -m ectf25.tv.list -h
usage: ectf25.tv.list [-h] port

List the channels with a subscription on the Decoder

positional arguments:
  port        Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)

options:
  -h, --help  show this help message and exit
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.tv.list /dev/tty.usbmodem11302
```

#### PowerShell

```
python -m ectf25.tv.list COM12
```

### Subscription Update Tool

The subscription update tool takes in an encoded update packet (in the form of a `.bin` file) and sends it to the
decoder.

```
python -m ectf25.tv.subscribe -h
usage: ectf25.tv.subscribe [-h] subscription_file port

Updates a Decoder's subscription.

positional arguments:
  subscription_file  Path to the subscription file created by ectf25_design.gen_subscription
  port               Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)

options:
  -h, --help         show this help message and exit
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.tv.subscribe subscription.bin /dev/tty.usbmodem11302
```

#### PowerShell

```
python -m ectf25.tv.subscribe subscription.bin COM12
```

### Tester Tool

The Tester tool can be used to test frame decoding functionality without the running the end to end infrastructure.

```
python -m ectf25.utils.tester -h
usage: ectf25.dev.tester [-h] --secrets SECRETS [--port PORT] [--delay DELAY] [--perf]
                         [--stub-encoder] [--stub-decoder] [--dump-raw DUMP_RAW]
                         [--dump-encoded DUMP_ENCODED] [--dump-decoded DUMP_DECODED]
                         {stdin,rand,json} ...

positional arguments:
  {stdin,rand,json}
    stdin               Read frames from stdin
    rand                Generate random frames
    json                Read frames from a json file like [[channel, frame, timestamp], ...]

options:
  -h, --help            show this help message and exit
  --secrets SECRETS, -s SECRETS
                        Path to the secrets file
  --port PORT, -p PORT  Serial port to the Decoder (See https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)
  --delay DELAY, -d DELAY
                        Delay after frame decoding
  --perf                Display performance stats
  --stub-encoder        Stub out encoder and pass frames directly to decoder
  --stub-decoder        Stub out decoder and print decoded frames
  --dump-raw DUMP_RAW   Dump raw frames to a file
  --dump-encoded DUMP_ENCODED
                        Dump encoded frames to a file
  --dump-decoded DUMP_DECODED
                        Dump decoded frames to a file
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.utils.tester --port /dev/tty.usbmodem11302 -s secrets/secrets.json rand -c 1 -f 64
```

#### PowerShell

```
python -m ectf25.utils.tester --port COM12 -s secrets\secrets.json rand -c 1 -f 64
```

## Running the Satellite and Encoder

To run all of the infrastructure, you will need to first start the uplink. Then, in a
separate terminal window, start the satellite. Finally, start a TV for every decoder
being tested while the satellite is running.

### Uplink

The uplink is the component of the Satellite TV system responsible for sending encoded
frames to the satellite. It will use the encoder from your design to encode frames.

```
python -m ectf25.uplink -h
usage: __main__.py [-h] secrets host port channels [channels ...]

positional arguments:
  secrets     Path to the secrets file
  host        TCP hostname to serve on
  port        TCP port to serve on
  channels    List of channel:fps:frames_file pairings (e.g., 1:10:channel1_frames.json
              2:20:channel2_frames.json)

options:
  -h, --help  show this help message and exit
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.uplink secrets/secrets.json localhost 2000 1:10:frames/x_c0.json
```

#### PowerShell

```
python -m ectf25.uplink secrets\secrets.json localhost 2000 1:10:frames/x_c0.json
```

### Satellite

The satellite is responsible for broadcasting all frames received from the uplink to all
listening TVs on the host computer.

```
python -m ectf25.satellite -h
usage: satellite.py [-h] up_host up_port down_host channels [channels ...]

positional arguments:
  up_host     Hostname for uplink
  up_port     Port for uplink
  down_host   Hostname for downlink
  channels    List of channel:down_port pairings (e.g., 1:2001 2:2002)

options:
  -h, --help  show this help message and exit
```

### **Example Utilization**

#### Linux and PowerShell

```bash
python -m ectf25.satellite localhost 2000 localhost 1:2001
```

### TV

The TV is responsible for sending encoded frames received from the satellite to a
decoder connected to the host computer and returning the decoded result.

```
python -m ectf25.tv.run -h
usage: ectf25.tv.run [-h] [--baud BAUD] sat_host sat_port dec_port

positional arguments:
  sat_host     TCP host of the satellite
  sat_port     TCP port of the satellite
  dec_port     Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)

options:
  -h, --help   show this help message and exit
  --baud BAUD  Baud rate of the serial port
```

### **Example Utilization**

#### Linux

```bash
python -m ectf25.tv.run localhost 2001 /dev/tty.usbmodem11302
```

#### PowerShell

```
python -m ectf25.tv.run localhost 2001 COM12
```
