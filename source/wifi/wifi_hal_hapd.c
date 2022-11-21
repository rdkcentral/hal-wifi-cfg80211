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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wifi_hal_hapd.h"

#if 0
#define DBG if (0) printf
#else
#define DBG printf
#endif

typedef struct {
    const char *name;
    size_t offset;
} field_map_t;

#define FIELD_DEF(name) {#name, offsetof(hapd_cfg_t, name)}

static field_map_t field_map[] = {
    FIELD_DEF(accept_mac_file),
    FIELD_DEF(ap_isolate),
    FIELD_DEF(ap_setup_locked),
    FIELD_DEF(auth_algs),
    FIELD_DEF(beacon_int),
    FIELD_DEF(bridge),
    FIELD_DEF(bss),
    FIELD_DEF(bssid),
    FIELD_DEF(bss_load_update_period),
    FIELD_DEF(bss_transition),
    FIELD_DEF(channel),
    FIELD_DEF(chan_util_avg_period),
    FIELD_DEF(config_methods),
    FIELD_DEF(country_code),
    FIELD_DEF(ctrl_interface),
    FIELD_DEF(disassoc_low_ack),
    FIELD_DEF(driver),
    FIELD_DEF(eap_server),
    FIELD_DEF(ht_capab),
    FIELD_DEF(hw_mode),
    FIELD_DEF(ieee80211ac),
    FIELD_DEF(ieee80211d),
    FIELD_DEF(ieee80211n),
    FIELD_DEF(ignore_broadcast_ssid),
    FIELD_DEF(interface),
    FIELD_DEF(logger_stdout),
    FIELD_DEF(logger_stdout_level),
    FIELD_DEF(logger_syslog),
    FIELD_DEF(logger_syslog_level),
    FIELD_DEF(macaddr_acl),
    FIELD_DEF(preamble),
    FIELD_DEF(rrm_neighbor_report),
    FIELD_DEF(ssid),
    FIELD_DEF(uapsd_advertisement_enabled),
    FIELD_DEF(vht_oper_centr_freq_seg0_idx),
    FIELD_DEF(vht_oper_chwidth),
    FIELD_DEF(wmm_enabled),
    FIELD_DEF(wpa),
    FIELD_DEF(wpa_key_mgmt),
    FIELD_DEF(wpa_pairwise),
    FIELD_DEF(wpa_passphrase),
    FIELD_DEF(wpa_psk_file),
    FIELD_DEF(wps_pin_requests),
    FIELD_DEF(wps_state)
};

static hapd_cfg_field_t *field_by_name(hapd_cfg_t *cfg, const char* field_name)
{
    int count = sizeof(field_map) / sizeof(*field_map);
    for (int i=0; i<count; i++)
    {
        if (0 == strcmp(field_map[i].name, field_name))
        {
            return (hapd_cfg_field_t*)((char*)cfg + field_map[i].offset);
        }
    }
    return NULL;
}

static hapd_cfg_field_t *field_by_index(hapd_cfg_t *cfg, unsigned index)
{
    unsigned count = sizeof(field_map) / sizeof(*field_map);
    if (index < count)
    {
        return (hapd_cfg_field_t*)((char*)cfg + field_map[index].offset);
    }
    return NULL;
}

static char* trim(char *str)
{
    const char *space=" \t\n\r";
    char *bgn;
    int len;

    for (bgn = str; *bgn != '\0' && strchr(space, *bgn) != NULL; bgn += 1);

    len = strlen(bgn);
    if (len > 0)
    {
        char *end;
        for (end = bgn + len - 1; end > bgn && strchr(space, *end) != NULL; end -= 1);
        end[1] = '\0';
    }
    return bgn;
}

static void hapd_parse_line(hapd_cfg_t *cfg, char *line, int line_index)
{
    char *key;
    char *value;
    hapd_cfg_field_t *field;

    key = line;
    value = strchr(line, '=');
    if (value == NULL)
    {
        DBG("Hapd: Missing value separator (line=%d)\n", line_index);
	    return;
    }
    *value++ = '\0';

    key = trim(key);
    if (strlen(key) == 0)
    {
	    DBG("Hapd: Hostapd configuration malformed (line=%d)\n", line_index);
	    return;
    }

    value = trim(value);
    if (strlen(value) == 0)
    {
        DBG("Hapd: Value not specified for the key='%s' (line=%d)\n", key, line_index);
	    return;
    }

    field = field_by_name(cfg, key);
    if (field)
    {
        free(field->value);
        field->value = strdup(value);
    }
    else
    {
        DBG("Hapd: Unknown hostapd configuration key='%s' (line=%d)\n", key, line_index);
    }
}

int hapd_reset_cfg(hapd_cfg_t *cfg)
{
    hapd_cfg_field_t *field;
    unsigned count = sizeof(field_map) / sizeof(*field_map);

    for (unsigned i=0; i<count; i++)
    {
        field = field_by_index(cfg, i);
        if (field)
        {
            free(field->value);
            field->value = NULL;
        }
    }

    cfg->valid = false;
    return 0;
}

int hapd_read_cfg(hapd_cfg_t *cfg, const char *filename)
{
    FILE *stream;
    char *buffer = NULL;
    char *line;
    int index = 0;
    size_t len = 0;
    ssize_t nread;

    // DBG("Hapd: Parse configuration '%s'\n", filename);
    stream = fopen(filename, "r");
    if (stream == NULL)
    {
        perror("fopen");
        return -1;
    }
    hapd_reset_cfg(cfg);
    while ((nread = getline(&buffer, &len, stream)) != -1)
    {
        index += 1;

        line = trim(buffer);
        if (line[0] == '#' || strlen(line) == 0) continue;
        hapd_parse_line(cfg, line, index);
    }
    free(buffer);
    fclose(stream);

    cfg->valid = true;
    return 0;
}

int hapd_write_cfg(hapd_cfg_t *cfg, const char *filename)
{
    hapd_cfg_field_t *field;
    unsigned count = sizeof(field_map) / sizeof(*field_map);
    FILE *fp;

    fp = fopen(filename, "w");
    if (fp == NULL)
    {
        perror("fopen");
        return -1;
    }

    for (unsigned i=0; i<count; i++)
    {
        field = field_by_index(cfg, i);
        if (field && field->value)
        {
            fprintf(fp, "%s=%s\n", field_map[i].name, field->value);
        }
    }

    fclose(fp);
    return 0;
}

int hapd_set_cfg(hapd_cfg_t *cfg, const char *param, const char *value)
{
    hapd_cfg_field_t *field = field_by_name(cfg, param);
    if (field)
    {
        free(field->value);
        field->value = strdup(value);
        return 0; 
    }
    return -1;
}

int hapd_get_cfg(hapd_cfg_t *cfg, const char *param, char *value, int value_size)
{
    hapd_cfg_field_t *field = field_by_name(cfg, param);
    if (field)
    {
        if (field->value)
        {
            snprintf(value, value_size, "%s", field->value);
        }
        else if (value_size > 0)
        {
            value[0] = '\0';
        }
        return 0; 
    }
    return -1;
}

void hapd_print_cfg(hapd_cfg_t *cfg)
{
    hapd_cfg_field_t *field;
    unsigned count = sizeof(field_map) / sizeof(*field_map);

    DBG("Hapd: config begin\n");
    for (unsigned i=0; i<count; i++)
    {
        field = field_by_index(cfg, i);
        if (field && field->value)
        {
            DBG("%s=%s\n", field_map[i].name, field->value);
        }
    }
    DBG("Hapd: config end\n");
}
