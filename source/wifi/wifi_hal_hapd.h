/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef __WIFI_HAL_HOSTAPD_H__
#define __WIFI_HAL_HOSTAPD_H__

typedef struct hapd_cfg_field_t {
    char *value;
} hapd_cfg_field_t;

typedef struct {
    bool valid;
    hapd_cfg_field_t accept_mac_file;
    hapd_cfg_field_t ap_isolate;
    hapd_cfg_field_t ap_pin;
    hapd_cfg_field_t ap_setup_locked;
    hapd_cfg_field_t auth_algs;
    hapd_cfg_field_t beacon_int;
    hapd_cfg_field_t bridge;
    hapd_cfg_field_t bss;
    hapd_cfg_field_t bssid;
    hapd_cfg_field_t bss_load_update_period;
    hapd_cfg_field_t bss_transition;
    hapd_cfg_field_t channel;
    hapd_cfg_field_t chan_util_avg_period;
    hapd_cfg_field_t config_methods;
    hapd_cfg_field_t country_code;
    hapd_cfg_field_t ctrl_interface;
    hapd_cfg_field_t disassoc_low_ack;
    hapd_cfg_field_t driver;
    hapd_cfg_field_t eap_server;
    hapd_cfg_field_t ht_capab;
    hapd_cfg_field_t hw_mode;
    hapd_cfg_field_t ieee80211ac;
    hapd_cfg_field_t ieee80211d;
    hapd_cfg_field_t ieee80211n;
    hapd_cfg_field_t interface;
    hapd_cfg_field_t ignore_broadcast_ssid;
    hapd_cfg_field_t logger_stdout;
    hapd_cfg_field_t logger_stdout_level;
    hapd_cfg_field_t logger_syslog;
    hapd_cfg_field_t logger_syslog_level;
    hapd_cfg_field_t macaddr_acl;
    hapd_cfg_field_t preamble;
    hapd_cfg_field_t rrm_neighbor_report;
    hapd_cfg_field_t ssid;
    hapd_cfg_field_t uapsd_advertisement_enabled;
    hapd_cfg_field_t vht_oper_centr_freq_seg0_idx;
    hapd_cfg_field_t vht_oper_chwidth;
    hapd_cfg_field_t wmm_enabled;
    hapd_cfg_field_t wpa;
    hapd_cfg_field_t wpa_key_mgmt;
    hapd_cfg_field_t wpa_pairwise;
    hapd_cfg_field_t wpa_passphrase;
    hapd_cfg_field_t wpa_psk_file;
    hapd_cfg_field_t wps_pin_requests;
    hapd_cfg_field_t wps_state;
} hapd_cfg_t;

int hapd_reset_cfg(hapd_cfg_t *cfg);
int hapd_write_cfg(hapd_cfg_t *cfg, const char *filename);
int hapd_read_cfg(hapd_cfg_t *cfg, const char *filename);

int hapd_set_cfg(hapd_cfg_t *cfg, const char *param, const char *value);
int hapd_get_cfg(hapd_cfg_t *cfg, const char *param, char *value, int value_size);

void hapd_print_cfg(hapd_cfg_t *cfg);

#endif
