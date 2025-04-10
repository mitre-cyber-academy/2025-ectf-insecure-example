/*****FIU MITRE eCTF 2025********************************************
*                                                                  *
*    decoder.c                                                     *
*                                                                  *
*   Author: Crypto Caballeros                                      *
*   Date: 2025                                                     *
*   Description: This file processes and verifies incoming files   *
*        to decode sattelite TV frames                             *
*                                                                  *
*******************************************************************/



/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "secret_keys.h"
#include "user_settings.h"
#include "simple_crypto.h"
#include "trng.h"

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_DECODER_ID_SIZE 8
#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF

// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF


/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/


// Tells the compiler not to pad the struct members
#pragma pack(push, 1) 

typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;

// Initialization Vector
    uint8_t iv[16];          
    
// Buffer for authentication
    uint8_t auth_tag[HASH_SIZE];   

// Holds data frame data
    uint8_t data[];              
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;

// Signature field from subscription signing
    uint8_t signature[HASH_SIZE]; 
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

// Tells the compiler to resume padding struct members
#pragma pack(pop) 

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {

    // if set to FLASH_FIRST_BOOT, device has booted before.
    uint32_t first_boot; 
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

// Previous frame timestamp for timestamp validation
timestamp_t prev_frame_timestamp = 0;


/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/


/***********************************************************************

@brief Checks whether the decoder is subscribed to a given channel
 
@param channel The channel number to be checked.
  
@return 1 if the the decoder is subscribed to the channel.  0 if not.

***********************************************************************/


int is_subscribed(channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }

    // Constant-time subscription check
    int result = 0;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // This boolean logic combines checks without branches
        int matches = (decoder_status.subscribed_channels[i].id == channel) ? 1 : 0;
        int is_active = decoder_status.subscribed_channels[i].active ? 1 : 0 ;

        // Or the result with matches AND is active, in constant time
        result |= (matches & is_active);
    }

    return result;
}

/********************************************************************************************************* 

   @brief Checks whether a frame timestamp is valid for the decoder's subscription to a given channel
 
   @param timestamp The timestamp to be checked.
   @param channel The channel number to be checked.
  
   @return 1 if the timestamp is valid for the channel.  0 if not.

*********************************************************************************************************/

int timestamp_valid(timestamp_t timestamp, channel_id_t channel) {

    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }

    // ensure timestamp is increasing monotonically
    if (timestamp <= prev_frame_timestamp) {
        STATUS_LED_ERROR();
        print_error("Timestamp invalid - non-monotonic.");
        return 0;
    }

    // Check if the timestamp is within the subscription window
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel) {
            if (decoder_status.subscribed_channels[i].start_timestamp <= timestamp && decoder_status.subscribed_channels[i].end_timestamp >= timestamp) {
                return 1;
            }
            else {
                STATUS_LED_ERROR();
                print_error("Timestamp invalid - outside of subscription window.");
                return 0;
            }
        }
    }
    return 0;
}

/*****************************************************************************

 @brief Performs a constant-time comparison of two buffers
  
 @param a First buffer
 @param b Second buffer
 @param len Length of buffers to compare
  
 @return 0 if equal, non-zero otherwise

 *******************************************************************************/

static int constant_time_memcmp(const void* a, const void* b, size_t len) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    unsigned char result = 0;

    for (size_t i = 0; i < len; i++) {
        // XOR each byte and OR the results together
       //  If all bytes are equal, result will be 0 
        result |= pa[i] ^ pb[i];
    }
    
    return (result != 0);
}

/**
 * @brief Add noise to power consumption to protect against power analysis attacks
 * 
 * This function executes random operations to mask power analysis during sensitive/cryptographic operations.
 * 
 */
static void add_power_noise(void) {
    // Create volatile buffers that won't be optimized out by compiler
    volatile uint8_t noise_buffer[32];
    volatile uint8_t result_buffer[32];
    
    // Use hardware TRNG to get random data
    for (int i = 0; i < sizeof(noise_buffer); i++) {
        MXC_TRNG_Random((uint8_t*)&noise_buffer[i], 1);
    }
    
    // Perform dummy arithmetic operations that consume power in a data-independent manner
    for (int i = 0; i < sizeof(noise_buffer); i++) {
        // Mix operations that consume different power
        result_buffer[i] = (noise_buffer[i] ^ 0x55);
        result_buffer[i] += (noise_buffer[(i+7) % sizeof(noise_buffer)] & 0xAA);
        result_buffer[i] *= (noise_buffer[(i+13) % sizeof(noise_buffer)] | 0x33);
        
        // Add compiler memory barriers to prevent optimization
        __asm__ volatile("" : : : "memory");
        
        // Ensure variable number of operations to create timing jitter
        uint8_t iterations = (noise_buffer[i] & 0x07) + 1;
        for (uint8_t j = 0; j < iterations; j++) {
            result_buffer[i] ^= (result_buffer[(i+j) % sizeof(result_buffer)] + j);
        }
    }
    
    // Force use of results to prevent compiler optimizations
    uint8_t checksum = 0;
    for (int i = 0; i < sizeof(result_buffer); i++) {
        checksum ^= result_buffer[i];
    }
    
    // Use the checksum in a way that doesn't affect program logic
    // but prevents the compiler from removing the code
    if (checksum == 0xFF) {
        // This branch almost never executes, but compiler can't prove it ;)
        __asm__ volatile("nop");
    }
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/***************************************************************
   @brief Lists out the actively subscribed channels over UART.
    @return 0 if successful.
***************************************************************/
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/***************************************************************************************

  @brief Updates the channel subscription for a subset of channels.

  @param pkt_len The length of the incoming packet
  @param update A pointer to an array of channel_update structs,
      which contains the channel number, start, and end timestamps
      for each channel being updated.

  @note Take care to note that this system is little endian.

  @return 0 upon success. -1 if error.

***************************************************************************************/

int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;

    // channel 0 is always available, 
   //  not able to be subscribed to since it is an emergency channel
   
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // Verify this update is for this decoder
    if (update->decoder_id != DECODER_ID) {
        STATUS_LED_ERROR();
        print_error("Failed to update subscription - wrong decoder ID\n");
        return -1;
    }

    // Create a buffer with the subscription data to verify signature
    uint8_t verify_buffer[sizeof(decoder_id_t) + sizeof(timestamp_t) * 2 + sizeof(channel_id_t)];
    uint8_t computed_hash[HASH_SIZE];
    uint8_t device_key[HASH_SIZE];

    // Copy data into verification buffer (all data except the siganture)
    memcpy(verify_buffer, &update->decoder_id, sizeof(decoder_id_t));
    memcpy(verify_buffer + sizeof(decoder_id_t), 
        &update->start_timestamp, sizeof(timestamp_t));
    memcpy(verify_buffer + sizeof(decoder_id_t) + sizeof(timestamp_t),
        &update->end_timestamp, sizeof(timestamp_t));
    memcpy(verify_buffer + sizeof(decoder_id_t) + sizeof(timestamp_t) * 2,
        &update->channel, sizeof(channel_id_t));

    // Get subscription/master key using the load_subscription_key 
    // mask power signal
    add_power_noise();
    uint8_t key_bytes[SUBSCRIPTION_KEY_SIZE];
    load_subscription_key(key_bytes);
    add_power_noise();
    // TODO: should any of this before HMAC have power noise?
    // Convert device ID to bytes (similar to Python format)
    uint8_t device_id_bytes[sizeof(decoder_id_t)]; // buffer for device id
    memcpy(device_id_bytes, &update->decoder_id, sizeof(decoder_id_t));

    // Create device-specific key input buffer
    uint32_t device_key_input_size = SUBSCRIPTION_KEY_SIZE + sizeof(decoder_id_t);
    uint8_t device_key_input[SUBSCRIPTION_KEY_SIZE + sizeof(decoder_id_t)];

    // Initialize device key input 
    memset(device_key_input, 0, device_key_input_size);
    memcpy(device_key_input, key_bytes, SUBSCRIPTION_KEY_SIZE); // Copy data
    memcpy(device_key_input + SUBSCRIPTION_KEY_SIZE, device_id_bytes, sizeof(decoder_id_t));

    // Hash to create device key (master key + device ID)
    memset(device_key, 0, HASH_SIZE);
    int hash_result = hash(device_key_input, device_key_input_size, device_key);

    if (hash_result != 0) {
        char error_buf[64];
        sprintf(error_buf, "WolfSSL hash returned error: %d", hash_result);
        print_debug(error_buf);
        STATUS_LED_ERROR();
        print_error("Failed to update subscription - hash computation error\n");
        return -1;
    }

    // Compute HMAC: H((device key ⊕ opad) || H((device key ⊕ ipad) || verify buffer))
    add_power_noise();
    hash_result = compute_hmac(device_key, HASH_SIZE, verify_buffer, sizeof(verify_buffer), computed_hash);

    if (hash_result != 0) {
        add_power_noise();
        char error_buf[64];
        sprintf(error_buf, "WolfSSL hash returned error: %d", hash_result);
        print_debug(error_buf);
        STATUS_LED_ERROR();
        print_error("Failed to update subscription - hash computation error\n");
        return -1;
    }

    // Securely clear the key from memory when done
    add_power_noise();
    secure_clear(key_bytes, SUBSCRIPTION_KEY_SIZE);
    secure_clear(device_key_input, device_key_input_size);

    // Verify the signature in constant time
    if (constant_time_memcmp(computed_hash, update->signature, HASH_SIZE) != 0) {

        // IPS DELAYS 5 SECONDS ON INVALID TIMESTAMP HASH
        MXC_Delay(MXC_DELAY_MSEC(5000));

        STATUS_LED_ERROR();
        print_error("Failed to update subscription - invalid signature\n");
        return -1;
    }

    // Find the first empty slot or existing subscripiton in the subscription array for this channel
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {

        //IPS DELAYS 5 SECONDS ON MAX SUBSCRIPTIONS
        MXC_Delay(MXC_DELAY_MSEC(5000));

        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    // Persist the updated subscription to flash
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));


    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}


/**********************************************************************
  @brief Processes a packet containing frame data.
 
  @param pkt_len A pointer to the incoming packet.
  @param new_frame A pointer to the incoming packet.
 
  @return 0 if successful.  -1 if data is from unsubscribed channel.

*********************************************************************/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};

    // Declaring variables for new frame
    channel_id_t channel = new_frame->channel; // channel of new frame
    timestamp_t timestamp = new_frame->timestamp; // timestamp of new frame

    // Calculate Components' Sizes

    // Header size - Ciphertext size - data
    uint16_t header_size = sizeof(new_frame->channel) 
                        + sizeof(new_frame->timestamp) 
                        + sizeof(new_frame->iv) + sizeof(new_frame->auth_tag);
    // Ciphertext size - the size of the packet minus 
    // the size of non-frame elements (header)
    uint16_t ciphertext_size = pkt_len - header_size;

    // Validate total packet length
    if (pkt_len < header_size) {
        MXC_Delay(MXC_DELAY_MSEC(5000));
        STATUS_LED_ERROR();
        print_error("Packet too small to contain authentication tag\n");
        return -1;
    }

    // Extract Components
    unsigned char *iv = new_frame->iv; // Extract IV (16 bytes)
    unsigned char *ciphertext = new_frame->data; // Extract Ciphertext
    unsigned char *auth_tag = new_frame->auth_tag; // Extract auth_tag (HMAC)

    // Verify HMAC first
    uint8_t computed_hmac[HASH_SIZE];
    uint8_t hmac_input[sizeof(channel_id_t) + sizeof(timestamp_t) + 16 + ciphertext_size];

    // Construct data in same manner as HMAC in encoder
    add_power_noise();
    memcpy(hmac_input, &new_frame->channel, sizeof(channel_id_t));
    memcpy(hmac_input + sizeof(channel_id_t), &new_frame->timestamp, sizeof(timestamp_t));
    memcpy(hmac_input + sizeof(channel_id_t) + sizeof(timestamp_t), iv, 16);
    memcpy(hmac_input + sizeof(channel_id_t) + sizeof(timestamp_t) + 16, ciphertext, ciphertext_size);

    // Get encryption key from secrets
    add_power_noise();
    uint8_t encryption_key[ENCRYPTION_KEY_SIZE];
    load_encryption_key(encryption_key);


    // Get MAC key from secrets

    uint8_t mac_key [MAC_KEY_SIZE];
    load_mac_key(mac_key);
    add_power_noise();

    // Compute HMAC
    compute_hmac(mac_key, MAC_KEY_SIZE, hmac_input, sizeof(hmac_input), computed_hmac);
    add_power_noise();
    // Verify HMAC in constant time
    if (constant_time_memcmp(computed_hmac, auth_tag, HASH_SIZE) != 0) {
        add_power_noise();
        secure_clear(mac_key, MAC_KEY_SIZE);
        MXC_Delay(MXC_DELAY_MSEC(5000));
        STATUS_LED_ERROR();
        print_error("Failed to authenticate frame - invalid signature\n");
        return -1;
    }
    add_power_noise();
    secure_clear(mac_key, MAC_KEY_SIZE); // clear mac key buffer
    
    //CHECKS IF SECURITY CHECKS PASSED

    // Check that we are subscribed to the channel...
    if (is_subscribed(channel)) {
        if (timestamp_valid(timestamp, channel)) {
            prev_frame_timestamp = timestamp;
        } else {
            //timestamp errors are printed in timestamp_valid()
            return -1;
        }

        // Before writing the bytes, decrypt
        uint8_t decrypted_data[FRAME_SIZE];
        int decrypted_size;

        add_power_noise();
        decrypted_size = aes_decrypt(ciphertext, ciphertext_size, encryption_key, iv, decrypted_data);
        if (decrypted_size < 0) {

            // clear encryption key
            add_power_noise();
            secure_clear(encryption_key, ENCRYPTION_KEY_SIZE); 

            // IPS DELAYS 5 SECONDS ON DECRYPTION FAILURE
            MXC_Delay(MXC_DELAY_MSEC(5000));

            STATUS_LED_ERROR();
            print_error("Decryption failed\n");
            return -1;
        }

        // clear encryption key
        add_power_noise();
        secure_clear(encryption_key, ENCRYPTION_KEY_SIZE); 
        write_packet(DECODE_MSG, decrypted_data, FRAME_SIZE); // 
        return 0;

    } else {
        STATUS_LED_ERROR();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

// @brief Initializes peripherals for system boot.
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        MXC_Delay(MXC_DELAY_MSEC(5000));
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }

    if (sizeof(decoder_id_t) > MAX_DECODER_ID_SIZE) {
        MXC_Delay(MXC_DELAY_MSEC(5000));
        print_error("Warning: Unexpected device ID size detected\n");
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
