# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

MXC_OPTIMIZE_CFLAGS = -Og

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto *******************

# wolfSSL file paths
VPATH += wolfssl/wolfcrypt/src
IPATH += wolfssl

# Minimal wolfSSL settings - rest of settings in user_settings.h
PROJ_CFLAGS += -DWOLFSSL_USER_SETTINGS
PROJ_CFLAGS += -DNO_WOLFSSL_DIR
PROJ_CFLAGS += -DNO_INLINE

# Hardware settings
PROJ_CFLAGS += -DUSE_HW_CRYPTO
PROJ_CFLAGS += -DCRYPTO_HW_ENABLED=1
