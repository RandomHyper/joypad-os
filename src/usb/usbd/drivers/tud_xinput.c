// tud_xinput.c - TinyUSB XInput class driver for Xbox 360
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Robert Dale Smith
//
// Custom USB device class driver implementing Xbox 360 XInput protocol
// with XSM3 console authentication support.
// XInput uses vendor class 0xFF, subclass 0x5D, protocol 0x01.
// Security uses vendor class 0xFF, subclass 0xFD, protocol 0x13.
//
// Multi-controller support: handles up to 4 XInput interfaces (Xbox 360 players 1-4)
//
// Reference: GP2040-CE, OGX-Mini (MIT/BSD-3-Clause)
// Auth: https://github.com/InvoxiPlayGames/libxsm3 (LGPL-2.1)

#include "tusb_option.h"

#if (CFG_TUD_ENABLED && CFG_TUD_XINPUT)

#include "tud_xinput.h"
#include <string.h>
#include "lib/libxsm3/xsm3.h"

// ============================================================================
// INTERNAL STATE
// ============================================================================

typedef struct {
    uint8_t itf_num;
    uint8_t ep_in;
    uint8_t ep_out;

    // Endpoint buffers
    CFG_TUD_MEM_ALIGN uint8_t ep_in_buf[CFG_TUD_XINPUT_EP_BUFSIZE];
    CFG_TUD_MEM_ALIGN uint8_t ep_out_buf[CFG_TUD_XINPUT_EP_BUFSIZE];

    // Current report data
    xinput_in_report_t in_report;
    xinput_out_report_t out_report;

    // Flags
    bool output_available;
} xinput_interface_t;

static xinput_interface_t _xinput_itf[4];  // Array for 4 controllers

// Security interface number (Interface 3)
static uint8_t _sec_itf_num = 0xFF;

// XSM3 auth state per slot
static xsm3_auth_state_t _auth_state[4] = {XSM3_AUTH_IDLE, XSM3_AUTH_IDLE, XSM3_AUTH_IDLE, XSM3_AUTH_IDLE};

// Auth data buffers per slot
static uint8_t _auth_buffer[4][48];    // Receive buffer for 0x82/0x87 data
static uint8_t _auth_response[4][48];  // Response buffer for 0x83
static uint8_t _auth_response_len[4];  // Response length for 0x83
static uint8_t _auth_request_id[4];    // Which request triggered processing

// ============================================================================
// HELPER: find slot by interface number
// ============================================================================

static uint8_t find_slot_by_itf(uint8_t itf_num)
{
    for (int i = 0; i < 4; i++) {
        if (_xinput_itf[i].itf_num == itf_num) return i;
    }
    return 0xFF;  // Not found
}

// ============================================================================
// CLASS DRIVER CALLBACKS
// ============================================================================

static void xinput_init(void)
{
    for (int i = 0; i < 4; i++) {
        memset(&_xinput_itf[i], 0, sizeof(_xinput_itf[i]));
        _xinput_itf[i].itf_num = 0xFF;
        _xinput_itf[i].ep_in = 0xFF;
        _xinput_itf[i].ep_out = 0xFF;

        // Initialize input report to neutral state
        _xinput_itf[i].in_report.report_id = 0x00;
        _xinput_itf[i].in_report.report_size = sizeof(xinput_in_report_t);

        _auth_state[i] = XSM3_AUTH_IDLE;
        _auth_response_len[i] = 0;
        _auth_request_id[i] = 0;
    }

    _sec_itf_num = 0xFF;
}

static bool xinput_deinit(void)
{
    return true;
}

static void xinput_reset(uint8_t rhport)
{
    (void)rhport;
    xinput_init();
}

static uint16_t xinput_open(uint8_t rhport, tusb_desc_interface_t const* itf_desc, uint16_t max_len)
{
    // Must be vendor class
    TU_VERIFY(itf_desc->bInterfaceClass == 0xFF, 0);

    uint16_t drv_len = sizeof(tusb_desc_interface_t);
    uint8_t const* p_desc = tu_desc_next((uint8_t const*)itf_desc);

    // --- Interface 0-3: Gamepad (SubClass 0x5D, Protocol 0x01) ---
    if (itf_desc->bInterfaceSubClass == XINPUT_INTERFACE_SUBCLASS &&
        itf_desc->bInterfaceProtocol == XINPUT_INTERFACE_PROTOCOL)
    {
        // Determine which slot (0-3) based on enumeration order
        static uint8_t gamepad_slot_counter = 0;
        uint8_t slot = gamepad_slot_counter;
        if (gamepad_slot_counter < 4) gamepad_slot_counter++;

        _xinput_itf[slot].itf_num = itf_desc->bInterfaceNumber;

        // Skip vendor descriptor (type 0x21)
        if (p_desc[1] == XINPUT_DESC_TYPE_VENDOR) {
            drv_len += tu_desc_len(p_desc);
            p_desc = tu_desc_next(p_desc);
        }

        // Open endpoints
        for (uint8_t i = 0; i < itf_desc->bNumEndpoints; i++) {
            tusb_desc_endpoint_t const* ep_desc = (tusb_desc_endpoint_t const*)p_desc;
            TU_VERIFY(TUSB_DESC_ENDPOINT == ep_desc->bDescriptorType, 0);
            TU_VERIFY(usbd_edpt_open(rhport, ep_desc), 0);

            if (tu_edpt_dir(ep_desc->bEndpointAddress) == TUSB_DIR_IN) {
                _xinput_itf[slot].ep_in = ep_desc->bEndpointAddress;
            } else {
                _xinput_itf[slot].ep_out = ep_desc->bEndpointAddress;
            }

            drv_len += sizeof(tusb_desc_endpoint_t);
            p_desc = tu_desc_next(p_desc);
        }

        // Start receiving on OUT endpoint
        if (_xinput_itf[slot].ep_out != 0xFF) {
            usbd_edpt_xfer(rhport, _xinput_itf[slot].ep_out, _xinput_itf[slot].ep_out_buf, sizeof(_xinput_itf[slot].ep_out_buf));
        }

        TU_LOG1("[XINPUT] Opened gamepad slot %u (itf %u), EP IN=0x%02X, EP OUT=0x%02X\r\n",
                slot, _xinput_itf[slot].itf_num, _xinput_itf[slot].ep_in, _xinput_itf[slot].ep_out);
    }
    // --- Interface 1: Audio (SubClass 0x5D, Protocol 0x03) ---
    else if (itf_desc->bInterfaceSubClass == XINPUT_INTERFACE_SUBCLASS &&
             itf_desc->bInterfaceProtocol == 0x03)
    {
        // Skip vendor descriptor (type 0x21)
        if (p_desc[1] == XINPUT_DESC_TYPE_VENDOR) {
            drv_len += tu_desc_len(p_desc);
            p_desc = tu_desc_next(p_desc);
        }

        // Skip 4 endpoints (stub - not opened)
        for (uint8_t i = 0; i < itf_desc->bNumEndpoints; i++) {
            drv_len += sizeof(tusb_desc_endpoint_t);
            p_desc = tu_desc_next(p_desc);
        }

        TU_LOG1("[XINPUT] Skipped audio itf %u (%u EPs)\r\n",
                itf_desc->bInterfaceNumber, itf_desc->bNumEndpoints);
    }
    // --- Interface 2: Plugin Module (SubClass 0x5D, Protocol 0x02) ---
    else if (itf_desc->bInterfaceSubClass == XINPUT_INTERFACE_SUBCLASS &&
             itf_desc->bInterfaceProtocol == 0x02)
    {
        // Skip vendor descriptor (type 0x21)
        if (p_desc[1] == XINPUT_DESC_TYPE_VENDOR) {
            drv_len += tu_desc_len(p_desc);
            p_desc = tu_desc_next(p_desc);
        }

        // Skip 1 endpoint (stub - not opened)
        for (uint8_t i = 0; i < itf_desc->bNumEndpoints; i++) {
            drv_len += sizeof(tusb_desc_endpoint_t);
            p_desc = tu_desc_next(p_desc);
        }

        TU_LOG1("[XINPUT] Skipped plugin itf %u (%u EPs)\r\n",
                itf_desc->bInterfaceNumber, itf_desc->bNumEndpoints);
    }
    // --- Interface 3: Security (SubClass 0xFD, Protocol 0x13) ---
    else if (itf_desc->bInterfaceSubClass == XINPUT_SEC_INTERFACE_SUBCLASS &&
             itf_desc->bInterfaceProtocol == XINPUT_SEC_INTERFACE_PROTOCOL)
    {
        _sec_itf_num = itf_desc->bInterfaceNumber;

        // Skip security descriptor (type 0x41)
        if (p_desc[1] == XINPUT_DESC_TYPE_SEC) {
            drv_len += tu_desc_len(p_desc);
            p_desc = tu_desc_next(p_desc);
        }

        // 0 endpoints for security interface
        TU_LOG1("[XINPUT] Opened security itf %u\r\n", _sec_itf_num);
    }
    else
    {
        return 0;  // Unknown interface, don't claim
    }

    TU_VERIFY(max_len >= drv_len, 0);
    return drv_len;
}

static bool xinput_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const* request)
{
    (void)rhport;
    (void)stage;
    (void)request;
    // Vendor-type requests (including XSM3 auth) are routed by TinyUSB to
    // tud_vendor_control_xfer_cb(), not here. See tud_xinput_vendor_control_xfer_cb().
    return true;
}

// ============================================================================
// VENDOR CONTROL REQUEST HANDLER (XSM3 Auth)
// ============================================================================
// TinyUSB routes vendor-type control requests to tud_vendor_control_xfer_cb()
// rather than to class driver control_xfer_cb. This function is called from
// tud_vendor_control_xfer_cb() in usbd.c when in XInput mode.

bool tud_xinput_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const* request)
{
    uint8_t slot = find_slot_by_itf(request->wIndex);  // wIndex is interface number
    if (slot >= 4) slot = 0;  // Default to slot 0 if not found

    if (request->bmRequestType_bit.direction == TUSB_DIR_IN) {
        // Device-to-host: respond on SETUP stage
        if (stage != CONTROL_STAGE_SETUP) return true;

        switch (request->bRequest) {
            case XSM3_REQ_GET_SERIAL: {
                // 0x81: Return 29-byte identification data
                TU_LOG1("[XINPUT] Slot %u: Auth: GET_SERIAL\r\n", slot);
                tud_control_xfer(rhport, request,
                                 (void*)xsm3_id_data_ms_controller,
                                 XSM3_SERIAL_LEN);
                return true;
            }

            case XSM3_REQ_RESPOND: {
                // 0x83: Return challenge response
                if (_auth_state[slot] == XSM3_AUTH_RESPONDED || _auth_state[slot] == XSM3_AUTH_AUTHENTICATED) {
                    TU_LOG1("[XINPUT] Slot %u: Auth: RESPOND (%u bytes)\r\n", slot, _auth_response_len[slot]);
                    tud_control_xfer(rhport, request, _auth_response[slot], _auth_response_len[slot]);
                } else {
                    TU_LOG1("[XINPUT] Slot %u: Auth: RESPOND (not ready, state=%u)\r\n", slot, _auth_state[slot]);
                    return false;  // STALL if not ready
                }
                return true;
            }

            case XSM3_REQ_KEEPALIVE: {
                // 0x84: Keepalive, zero-length response
                TU_LOG1("[XINPUT] Slot %u: Auth: KEEPALIVE\r\n", slot);
                tud_control_xfer(rhport, request, NULL, 0);
                return true;
            }

            case XSM3_REQ_STATE: {
                // 0x86: Return auth state (2 bytes)
                static uint16_t state_val;
                state_val = (_auth_state[slot] == XSM3_AUTH_RESPONDED ||
                             _auth_state[slot] == XSM3_AUTH_AUTHENTICATED) ? 2 : 1;
                TU_LOG1("[XINPUT] Slot %u: Auth: STATE=%u\r\n", slot, state_val);
                tud_control_xfer(rhport, request, &state_val, sizeof(state_val));
                return true;
            }

            default:
                TU_LOG2("[XINPUT] Slot %u: Auth: Unknown IN req 0x%02X\r\n", slot, request->bRequest);
                return false;
        }
    } else {
        // Host-to-device: accept data on SETUP, process on DATA stage
        if (stage == CONTROL_STAGE_SETUP) {
            // Accept the data phase
            tud_control_xfer(rhport, request, _auth_buffer[slot], request->wLength);
            return true;
        } else if (stage == CONTROL_STAGE_DATA) {
            switch (request->bRequest) {
                case XSM3_REQ_INIT_AUTH: {
                    // 0x82: Console sends 34-byte challenge init
                    TU_LOG1("[XINPUT] Slot %u: Auth: INIT_AUTH (%u bytes)\r\n", slot, request->wLength);
                    _auth_request_id[slot] = XSM3_REQ_INIT_AUTH;
                    _auth_state[slot] = XSM3_AUTH_INIT_RECEIVED;
                    return true;
                }

                case XSM3_REQ_VERIFY: {
                    // 0x87: Console sends 22-byte verify challenge
                    TU_LOG1("[XINPUT] Slot %u: Auth: VERIFY (%u bytes)\r\n", slot, request->wLength);
                    _auth_request_id[slot] = XSM3_REQ_VERIFY;
                    _auth_state[slot] = XSM3_AUTH_VERIFY_RECEIVED;
                    return true;
                }

                default:
                    TU_LOG2("[XINPUT] Slot %u: Auth: Unknown OUT req 0x%02X\r\n", slot, request->bRequest);
                    return false;
            }
        }
        return true;  // ACK status stage
    }
}

static bool xinput_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes)
{
    (void)result;

    // Find which slot this endpoint belongs to
    for (int slot = 0; slot < 4; slot++) {
        if (ep_addr == _xinput_itf[slot].ep_out) {
            // Received rumble/LED data on OUT endpoint
            if (xferred_bytes >= sizeof(xinput_out_report_t)) {
                memcpy(&_xinput_itf[slot].out_report, _xinput_itf[slot].ep_out_buf, sizeof(xinput_out_report_t));
                _xinput_itf[slot].output_available = true;
            }

            // Queue next receive
            usbd_edpt_xfer(rhport, _xinput_itf[slot].ep_out, _xinput_itf[slot].ep_out_buf, sizeof(_xinput_itf[slot].ep_out_buf));
            return true;
        }
    }

    return true;
}

// ============================================================================
// CLASS DRIVER STRUCT
// ============================================================================

static const usbd_class_driver_t _xinput_class_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "XINPUT",
#else
    .name = NULL,
#endif
    .init             = xinput_init,
    .deinit           = xinput_deinit,
    .reset            = xinput_reset,
    .open             = xinput_open,
    .control_xfer_cb  = xinput_control_xfer_cb,
    .xfer_cb          = xinput_xfer_cb,
    .sof              = NULL,
};

const usbd_class_driver_t* tud_xinput_class_driver(void)
{
    return &_xinput_class_driver;
}

// ============================================================================
// PUBLIC API
// ============================================================================

// Legacy single-slot API (defaults to slot 0 for backward compatibility)
bool tud_xinput_ready(void)
{
    return tud_xinput_ready_slot(0);
}

bool tud_xinput_send_report(const xinput_in_report_t* report)
{
    return tud_xinput_send_report_slot(0, report);
}

bool tud_xinput_get_output(xinput_out_report_t* output)
{
    return tud_xinput_get_output_slot(0, output);
}

// Multi-slot APIs
bool tud_xinput_ready_slot(uint8_t slot)
{
    if (slot >= 4) return false;
    return tud_ready() &&
           (_xinput_itf[slot].ep_in != 0xFF) &&
           !usbd_edpt_busy(0, _xinput_itf[slot].ep_in);
}

bool tud_xinput_send_report_slot(uint8_t slot, const xinput_in_report_t* report)
{
    TU_VERIFY(report != NULL);
    TU_VERIFY(slot < 4);
    TU_VERIFY(tud_xinput_ready_slot(slot));

    // Update internal report state
    memcpy(&_xinput_itf[slot].in_report, report, sizeof(xinput_in_report_t));

    // Copy to endpoint buffer
    memcpy(_xinput_itf[slot].ep_in_buf, report, sizeof(xinput_in_report_t));

    // Wake host if suspended
    if (tud_suspended()) {
        tud_remote_wakeup();
    }

    return usbd_edpt_xfer(0, _xinput_itf[slot].ep_in, _xinput_itf[slot].ep_in_buf, sizeof(xinput_in_report_t));
}

bool tud_xinput_get_output_slot(uint8_t slot, xinput_out_report_t* output)
{
    TU_VERIFY(output != NULL);
    TU_VERIFY(slot < 4);

    if (_xinput_itf[slot].output_available) {
        memcpy(output, &_xinput_itf[slot].out_report, sizeof(xinput_out_report_t));
        _xinput_itf[slot].output_available = false;
        return true;
    }

    return false;
}

// ============================================================================
// XSM3 AUTH
// ============================================================================

void tud_xinput_xsm3_init(void)
{
    xsm3_initialise_state();
    xsm3_set_identification_data(xsm3_id_data_ms_controller);
    for (int i = 0; i < 4; i++) {
        _auth_state[i] = XSM3_AUTH_IDLE;
        _auth_response_len[i] = 0;
        _auth_request_id[i] = 0;
    }
    TU_LOG1("[XINPUT] XSM3 auth initialized for 4 slots\r\n");
}

void tud_xinput_xsm3_process(void)
{
    for (int slot = 0; slot < 4; slot++) {
        if (_auth_state[slot] == XSM3_AUTH_INIT_RECEIVED &&
            _auth_request_id[slot] == XSM3_REQ_INIT_AUTH)
        {
            // Process challenge init (34 bytes in _auth_buffer[slot])
            xsm3_do_challenge_init(_auth_buffer[slot]);
            // Copy response (header + 0x28 payload + checksum = 0x2E = 46 bytes)
            _auth_response_len[slot] = XSM3_RESPONSE_INIT_LEN;
            memcpy(_auth_response[slot], xsm3_challenge_response, _auth_response_len[slot]);
            _auth_state[slot] = XSM3_AUTH_RESPONDED;
            _auth_request_id[slot] = 0;
            TU_LOG1("[XINPUT] Slot %u: XSM3 challenge init processed, response ready (%u bytes)\r\n",
                    slot, _auth_response_len[slot]);
        }
        else if (_auth_state[slot] == XSM3_AUTH_VERIFY_RECEIVED &&
                 _auth_request_id[slot] == XSM3_REQ_VERIFY)
        {
            // Process verify challenge (22 bytes in _auth_buffer[slot])
            xsm3_do_challenge_verify(_auth_buffer[slot]);
            // Copy response (header + 0x10 payload + checksum = 0x16 = 22 bytes)
            _auth_response_len[slot] = XSM3_RESPONSE_VERIFY_LEN;
            memcpy(_auth_response[slot], xsm3_challenge_response, _auth_response_len[slot]);
            _auth_state[slot] = XSM3_AUTH_AUTHENTICATED;
            _auth_request_id[slot] = 0;
            TU_LOG1("[XINPUT] Slot %u: XSM3 verify processed, auth complete (%u bytes)\r\n",
                    slot, _auth_response_len[slot]);
        }
    }
}

#endif // CFG_TUD_ENABLED && CFG_TUD_XINPUT
