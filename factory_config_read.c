/*
 * Copyright 2016-2022, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

/** @file
 *
 * This file implements the interface to read data from the flash Static Section.
 *
 */
#include "wiced_bt_dev.h"
#include "wiced_bt_trace.h"
#include "wiced_platform.h"
#if CYW20819A1 || CYW20820A1 || CYW20719B2 || CYW20721B2 || CYW30739A0
#include "wiced_hal_eflash.h"
#elif CYW20706A2 || CYW20735B1  || CYW43012C0 || CYW20835B1 || BTSTACK_VER >= 0x03000001
#include "wiced_hal_sflash.h"
#endif
#include "wiced_bt_factory_app_config.h"

/*****************************************************************************
**  Constants
*****************************************************************************/
#define SS_READ_LIMIT (8*1024)
#define SS_READ_CHUNK (32)

/*****************************************************************************
**  Data types
*****************************************************************************/
typedef enum
{
    SS_SEEK_FE,
    SS_SEEK_00_1,
    SS_SEEK_00_2,
    SS_SEEK_TYPE,
    SS_TYPE_LEN1,
    SS_TYPE_LEN2,
    SS_SKIP_LEN1,
    SS_SKIP_LEN2,
    SS_SKIP,
    SS_COPY,
    SS_DONE
} static_data_parse_state;

/******************************************************
 *               Function Definitions
 ******************************************************/

/**
 * @brief Read record from manufacturer static memory
 *
 * @param item_type     - record designated tag
 * @param buffer        - pointer to the memory buffer to store the record
 * @param read_length   - number of bytes to read
 * @param read_offset   - start offset to read the record
 * @return uint16_t     - number of bytes that was actually read to the buffer
 */
uint16_t wiced_bt_factory_config_read(uint8_t item_type, uint8_t* buffer, uint16_t read_length, uint16_t read_offset, uint16_t * record_size)
{
    uint16_t i;
    uint16_t copy_len = 0;
    uint16_t len = 0;
    uint16_t offset = 0;
    static_data_parse_state state = SS_SEEK_FE;
    uint8_t flash_read_buffer[SS_READ_CHUNK];
    *record_size = 0;

    if( (item_type >= WICED_BT_FACTORY_CONFIG_ITEM_FIRST) &&
        (item_type <= WICED_BT_FACTORY_CONFIG_ITEM_LAST))
    {
        while((state != SS_DONE) && (offset < (SS_READ_LIMIT)))
        {
#if CYW20819A1 || CYW20820A1 || CYW20719B2 || CYW20721B2 || CYW30739A0
            if(WICED_SUCCESS != wiced_hal_eflash_read(offset, (uint8_t *)flash_read_buffer, sizeof(flash_read_buffer)))
#elif CYW20706A2 || CYW20735B1  || CYW43012C0 || CYW20835B1 || BTSTACK_VER >= 0x03000001
            if(sizeof(flash_read_buffer) != wiced_hal_sflash_read(offset, sizeof(flash_read_buffer), flash_read_buffer))
#else
#error unexpected device type
#endif
            {
                WICED_BT_TRACE("bad flash read\n");
                break;
            }
            offset += sizeof(flash_read_buffer);
            for(i=0; i < sizeof(flash_read_buffer); i++)
            {
                uint8_t byte = flash_read_buffer[i];
                //WICED_BT_TRACE("flash @%d = %02x, state %d\n", offset+i, byte, state);
                switch(state)
                {
                case SS_SEEK_FE:
                    if(byte == 0xfe)
                    {
                        state = SS_SEEK_00_1;
                    }
                    break;
                case SS_SEEK_00_1:
                    state = (byte == 0) ? SS_SEEK_00_2: SS_SEEK_FE;
                    break;
                case SS_SEEK_00_2:
                    state = (byte == 0) ? SS_SEEK_TYPE : SS_SEEK_FE;
                    break;
                case SS_SEEK_TYPE:
                    state = (byte == item_type) ? SS_TYPE_LEN1 : ((byte != 0xFF) && (byte > 0x80)) ? SS_SKIP_LEN1 : SS_DONE;
                    break;
                case SS_TYPE_LEN1:
                    len = byte;
                    state = SS_TYPE_LEN2;
                    break;
                case SS_SKIP_LEN1:
                    len = byte;
                    state = SS_SKIP_LEN2;
                    break;
                case SS_TYPE_LEN2:
                    len += byte << 8;
                    *record_size = len;
                    state = (read_offset >= len) ? SS_DONE : SS_COPY;
                    len = ((read_length + read_offset) <= len) ? read_length : len - read_offset;
                    break;
                case SS_SKIP_LEN2:
                    len += byte << 8;
                    state = SS_SKIP;
                    break;
                case SS_SKIP:
                    if(--len == 0)
                    {
                        state = SS_SEEK_TYPE;
                    }
                    break;
                case SS_COPY:
                    if (0 == read_offset)
                    {
                        if(len-- == 0)
                        {
                            state = SS_DONE;
                        }
                        else
                        {
                            *buffer++ = byte;
                            copy_len++;
                        }
                    }
                    else
                    {
                        --read_offset;
                    }
                    break;
                case SS_DONE:
                    break;
                default:
                    state = SS_SEEK_FE;
                    break;
                }
            }
        }
    }
    return copy_len;
}


/**
 * @brief Get list of provisioning records from manufacturer static memory
 *
 * @param buffer[out]        - pointer to the memory buffer to store the record list
 * @return uint16_t          - number of found provisioning records
 */
uint16_t wiced_bt_factory_config_provisioning_records_get(uint16_t* buffer)
{
    uint16_t count = 0;
    for (uint16_t i = 0; i < WICED_BT_FACTORY_PROVISIONING_RECORD_SIZE; i++)
    {
        /* try to read only one first byte of the record to probe */
        uint16_t record_size;
        uint8_t byte;
        if(0 != wiced_bt_factory_config_read((WICED_BT_FACTORY_PROVISIONING_RECORD_OFFSET + i) & 0xff, &byte, 1, 0, &record_size))
        {
            *buffer++ = i;
            count++;
        }
    }
    return count;
}


/**
 * @brief Get provisioning record from manufacturer static memory
 *
 * @param[in]  item_type        - record designated tag
 * @param[out] buffer           - pointer to the memory buffer to store the record
 * @param[in]  fragment_length  - number of bytes to read
 * @param[in]  fragment_offset  - start offset to read the record
 * @param[out] record_size      - pointer to the output parameter to store total record size
 * @return uint16_t             - number of bytes that was actually read to the buffer
 */
uint16_t wiced_bt_factory_config_provisioning_record_req(uint16_t record_id, uint8_t *buffer, uint16_t fragment_length, uint16_t fragment_offset, uint16_t * record_size)
{
    uint8_t item_type = (uint8_t)((record_id + WICED_BT_FACTORY_PROVISIONING_RECORD_OFFSET) & 0xff);
    return wiced_bt_factory_config_read(item_type, buffer, fragment_length, fragment_offset, record_size);
}
