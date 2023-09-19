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

/*
* Material from the TR181 data model is Copyright (c) 2010-2017, Broadband Forum
* Licensed under the BSD-3 license
*/

/*
* This file includes material that is Copyright (c) 2020, Plume Design Inc.
* Licensed under the BSD-3 license
*/

/* Code in rxStatsInfo_callback and other callbacks is credited as follows:
Copyright (c) 2007, 2008    Johannes Berg
Copyright (c) 2007        Andy Lutomirski
Copyright (c) 2007        Mike Kershaw
Copyright (c) 2008-2009        Luis R. Rodriguez
Licensed under the ISC license
*/

#define HAL_NETLINK_IMPL
#define _GNU_SOURCE /* needed for strcasestr */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_hal_hapd.h"

#ifdef HAL_NETLINK_IMPL
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h>
#endif

#include <ev.h>
#include <wpa_ctrl.h>
#include <errno.h>
#include <time.h>
#define MAC_ALEN 6

#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define MAX_POSSIBLE_CHANNEL_STRING_BUF 512
#define IF_NAME_SIZE 50
#define CONFIG_PREFIX "/nvram/hostapd"
#define ACL_PREFIX "/tmp/hostapd-acl"
//#define ACL_PREFIX "/tmp/wifi_acl_list" //RDKB convention
#define SOCK_PREFIX "/var/run/hostapd/wifi"
#define VAP_STATUS_FILE "/tmp/vap-status"
#define DRIVER_2GHZ "ath9k"
#define DRIVER_5GHZ "ath10k_pci"

/*
   MAX_APS - Number of all AP available in system
   2x Home AP
   2x Backhaul AP
   2x Guest AP
   2x Secure Onboard AP
   2x Service AP

*/
#define MAX_APS 10
#define NUMBER_OF_RADIOS 2

#ifndef AP_PREFIX
#define AP_PREFIX	"wifi"
#endif

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wlan"
#endif

#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024

//Uncomment to enable debug logs
//#define WIFI_DEBUG

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#define WIFI_ENTRY_EXIT_DEBUG printf
#else
#define wifi_dbg_printf(format, args...) printf("")
#define WIFI_ENTRY_EXIT_DEBUG(format, args...) printf("")
#endif

#define AP_IDX_2G_PRIVATE  0
#define AP_IDX_2G_PUBLIC   4
#define AP_IDX_5G_PRIVATE  1
#define AP_IDX_5G_PUBLIC   5

#define LM_DHCP_CLIENT_FORMAT   "%63d %17s %63s %63s"

#define HOSTAPD_HT_CAPAB_20 "[SHORT-GI-20]"
#define HOSTAPD_HT_CAPAB_40 "[SHORT-GI-20][SHORT-GI-40]"

#define BW_FNAME "/nvram/bw_file.txt"

#define PS_MAX_TID 16

static wifi_radioQueueType_t _tid_ac_index_get[PS_MAX_TID] = {
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 0 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 1 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 2 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 3 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 4 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 5 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 6 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 7 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 8 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 9 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 10 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 11 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 12 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 13 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 14 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 15 */
};

static hapd_cfg_t hapd_conf[MAX_APS] = {{0}};

typedef unsigned long long  u64;

/* Enum to define WiFi Bands */
typedef enum
{
    band_invalid = -1,
    band_2_4 = 0,
    band_5 = 1,
} wifi_band;

#ifdef WIFI_HAL_VERSION_3

// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

#ifndef ARRAY_AND_SIZE
#define ARRAY_AND_SIZE(x)   (x),ARRAY_SIZE(x)
#endif /* ARRAY_AND_SIZE */

#define WIFI_ITEM_STR(key, str)        {0, sizeof(str)-1, (int)key, (intptr_t)str}

typedef struct {
    int32_t         value;
    int32_t         param;
    intptr_t        key;
    intptr_t        data;
} wifi_secur_list;

wifi_secur_list *       wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key);
wifi_secur_list *       wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str);
char *                  wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key);

static wifi_secur_list map_security[] =
{
    WIFI_ITEM_STR(wifi_security_mode_none,                    "None"),
    WIFI_ITEM_STR(wifi_security_mode_wep_64,                  "WEP-64"),
    WIFI_ITEM_STR(wifi_security_mode_wep_128,                 "WEP-128"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_personal,            "WPA-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_enterprise,          "WPA-Enterprise"),
    WIFI_ITEM_STR(wifi_security_mode_wpa2_personal,           "WPA2-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa2_enterprise,         "WPA2-Enterprise"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_wpa2_personal,       "WPA-WPA2-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_wpa2_enterprise,     "WPA-WPA2-Enterprise")
};

wifi_secur_list * wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key)
{
    wifi_secur_list    *item;
    int                i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if ((int)(item->key) == key) {
            return item;
        }
    }

    return NULL;
}

char * wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key)
{
    wifi_secur_list    *item = wifi_get_item_by_key(list, list_sz, key);

    if (!item) {
        return "";
    }

    return (char *)(item->data);
}

wifi_secur_list * wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str)
{
    wifi_secur_list    *item;
    int                i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if (strcmp((char *)(item->data), str) == 0) {
            return item;
        }
    }

    return NULL;
}
#endif /* WIFI_HAL_VERSION_3 */

#ifdef HAL_NETLINK_IMPL
typedef struct {
    int id;
    struct nl_sock* socket;
    struct nl_cb* cb;
} Netlink;

static int mac_addr_aton(unsigned char *mac_addr, char *arg)
{
    unsigned int mac_addr_int[6]={};
    sscanf(arg, "%x:%x:%x:%x:%x:%x", mac_addr_int+0, mac_addr_int+1, mac_addr_int+2, mac_addr_int+3, mac_addr_int+4, mac_addr_int+5);
    mac_addr[0] = mac_addr_int[0];
    mac_addr[1] = mac_addr_int[1];
    mac_addr[2] = mac_addr_int[2];
    mac_addr[3] = mac_addr_int[3];
    mac_addr[4] = mac_addr_int[4];
    mac_addr[5] = mac_addr_int[5];
    return 0;
}

static void mac_addr_ntoa(char *mac_addr, unsigned char *arg)
{
    unsigned int mac_addr_int[6]={};
    mac_addr_int[0] = arg[0];
    mac_addr_int[1] = arg[1];
    mac_addr_int[2] = arg[2];
    mac_addr_int[3] = arg[3];
    mac_addr_int[4] = arg[4];
    mac_addr_int[5] = arg[5];
    snprintf(mac_addr, 20, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr_int[0], mac_addr_int[1],mac_addr_int[2],mac_addr_int[3],mac_addr_int[4],mac_addr_int[5]);
    return;
}

static int ieee80211_frequency_to_channel(int freq)
{
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000)
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}

static int initSock80211(Netlink* nl) {
    nl->socket = nl_socket_alloc();
    if (!nl->socket) {
        fprintf(stderr, "Failing to allocate the  sock\n");
        return -ENOMEM;
    }

    nl_socket_set_buffer_size(nl->socket, 8192, 8192);

    if (genl_connect(nl->socket)) {
        fprintf(stderr, "Failed to connect\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOLINK;
    }

    nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
    if (nl->id< 0) {
        fprintf(stderr, "interface not found.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOENT;
    }

    nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
    if ((!nl->cb)) {
        fprintf(stderr, "Failed to allocate netlink callback.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return ENOMEM;
    }

    return nl->id;
}

static int nlfree(Netlink *nl)
{
    nl_cb_put(nl->cb);
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
    return 0;
}

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED }
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
};

static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
};

typedef struct _wifi_channelStats_loc {
    INT array_size;
    INT  ch_number;
    BOOL ch_in_pool;
    INT  ch_noise;
    BOOL ch_radar_noise;
    INT  ch_max_80211_rssi;
    INT  ch_non_80211_noise;
    INT  ch_utilization;
    ULLONG ch_utilization_total;
    ULLONG ch_utilization_busy;
    ULLONG ch_utilization_busy_tx;
    ULLONG ch_utilization_busy_rx;
    ULLONG ch_utilization_busy_self;
    ULLONG ch_utilization_busy_ext;
} wifi_channelStats_t_loc;

typedef struct wifi_device_info {
    INT  wifi_devIndex;
    UCHAR wifi_devMacAddress[6];
    CHAR wifi_devIPAddress[64];
    BOOL wifi_devAssociatedDeviceAuthentiationState;
    INT  wifi_devSignalStrength;
    INT  wifi_devTxRate;
    INT  wifi_devRxRate;
} wifi_device_info_t;

#endif

//For 5g Alias Interfaces
static BOOL priv_flag = TRUE;
static BOOL pub_flag = TRUE;
static BOOL Radio_flag = TRUE;
//wifi_setApBeaconRate(1, beaconRate);

struct params
{
    char * name;
    char * value;
};

static int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0, cmd_ret=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if((f = popen(cmd, "r")) == NULL) {
        fprintf(stderr,"\npopen %s error\n", cmd);
        return RETURN_ERR;
    }

    while(!feof(f))
    {
        *ptr = 0;
        if(bufSize>=128) {
            bufbytes=128;
        } else {
            bufbytes=bufSize-1;
        }

        fgets(ptr,bufbytes,f);
        readbytes=strlen(ptr);

        if(!readbytes)
            break;

        bufSize-=readbytes;
        ptr += readbytes;
    }
    cmd_ret = pclose(f);
    retBuf[retBufSize-1]=0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return cmd_ret >> 8;
}

static int wifi_hostapdCheck(int apIndex)
{
    char fname[MAX_BUF_SIZE];

    if (apIndex >= MAX_APS)
        return RETURN_ERR;

    // TODO: verify if data is consistent with configuration file content,
    // then no need to read again (note potential opensync / wifiagent race).
    snprintf(fname, sizeof(fname), "%s%d.conf", CONFIG_PREFIX, apIndex);
    return hapd_read_cfg(hapd_conf + apIndex, fname);
}

static int wifi_hostapdRead(int apIndex, char *param, char *output, int outputSize)
{
    if (RETURN_OK != wifi_hostapdCheck(apIndex))
        return RETURN_ERR;

    return hapd_get_cfg(hapd_conf + apIndex, param, output, outputSize);
}

static int wifi_hostapdWrite(int apIndex, struct params *list, int listSize)
{
    char fname[MAX_BUF_SIZE];

    if (RETURN_OK != wifi_hostapdCheck(apIndex))
        return RETURN_ERR;

    for (int i=0; i<listSize; i++)
    {
        if (RETURN_OK != hapd_set_cfg(hapd_conf + apIndex, list[i].name, list[i].value))
            return RETURN_ERR;
    }

    snprintf(fname, sizeof(fname), "%s%d.conf", CONFIG_PREFIX, apIndex);
    return hapd_write_cfg(hapd_conf + apIndex, fname);
}

static int wifi_hostapdProcessUpdate(int apIndex, struct params *list, int listSize)
{
    char cmd[MAX_CMD_SIZE]="";
    char buf[32]="";
    FILE *fp;
    //NOTE RELOAD should be done in ApplySSIDSettings

    for (int i=0; i<listSize; i++)
    {
        snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s%d SET %s %s", AP_PREFIX, apIndex, list[i].name, list[i].value);
        if ((fp = popen(cmd, "r"))==NULL)
        {
            perror("popen failed");
            return RETURN_ERR;
        }
        if (!fgets(buf, sizeof(buf), fp) || strncmp(buf, "OK", 2))
        {
            pclose(fp);
            perror("fgets failed");
            return RETURN_ERR;
        }
	    pclose(fp);
    }
    return RETURN_OK;
}

static int wifi_reloadAp(int apIndex)
{
    char cmd[MAX_CMD_SIZE]="";
    char buf[MAX_BUF_SIZE]="";

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d reload", AP_PREFIX, apIndex);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d disable", AP_PREFIX, apIndex);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d enable", AP_PREFIX, apIndex);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    return RETURN_OK;
}


//For Getting Current Interface Name from corresponding hostapd configuration
INT GetInterfaceName(int apIndex, char *interface_name)
{
    int res;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    res = wifi_hostapdRead(apIndex, "interface", interface_name, IF_NAME_SIZE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return res;
}

INT File_Reading(CHAR *file, char *Value)
{
    FILE *fp = NULL;
    char buf[MAX_CMD_SIZE] = {0}, copy_buf[MAX_CMD_SIZE] ={0};
    int count = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    fp = popen(file,"r");
    if(fp == NULL)
        return RETURN_ERR;

    if(fgets(buf,sizeof(buf) -1,fp) != NULL)
    {
        for(count=0;buf[count]!='\n';count++)
            copy_buf[count]=buf[count];
        copy_buf[count]='\0';
    }
    strcpy(Value,copy_buf);
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

void wifi_RestartHostapd_2G()
{
    int Public2GApIndex = 4;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Public2GApIndex, FALSE);
    wifi_setApEnable(Public2GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartHostapd_5G()
{
    int Public5GApIndex = 5;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Public5GApIndex, FALSE);
    wifi_setApEnable(Public5GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_2G()
{
    int PrivateApIndex = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(PrivateApIndex, FALSE);
    wifi_setApEnable(PrivateApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_5G()
{
    int Private5GApIndex = 1;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Private5GApIndex, FALSE);
    wifi_setApEnable(Private5GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static int writeBandWidth(int radioIndex,char *bw_value)
{
    char buf[MAX_BUF_SIZE];
    char cmd[MAX_CMD_SIZE];

    snprintf(cmd, sizeof(cmd), "grep SET_BW%d %s", radioIndex, BW_FNAME);
    if(_syscmd(cmd, buf, sizeof(buf)))
    {
        snprintf(cmd, sizeof(cmd), "echo SET_BW%d=%s >> %s", radioIndex, bw_value, BW_FNAME);
        _syscmd(cmd, buf, sizeof(buf));
        return RETURN_OK;
    }

    sprintf(cmd,"sed -i 's/^SET_BW%d=.*$/SET_BW%d=%s/' %s",radioIndex,radioIndex,bw_value,BW_FNAME);
    _syscmd(cmd,buf,sizeof(buf));
    return RETURN_OK;
}

static int readBandWidth(int radioIndex,char *bw_value)
{
    char buf[MAX_BUF_SIZE];
    char cmd[MAX_CMD_SIZE];
    sprintf(cmd,"grep 'SET_BW%d=' %s | sed 's/^.*=//'",radioIndex,BW_FNAME);
    _syscmd(cmd,buf,sizeof(buf));
    if(NULL!=strstr(buf,"20MHz"))
    {
        strcpy(bw_value,"20MHz");
    }
    else if(NULL!=strstr(buf,"40MHz"))
    {
        strcpy(bw_value,"40MHz");
    }
    else if(NULL!=strstr(buf,"80MHz"))
    {
        strcpy(bw_value,"80MHz");
    }
    else
    {
        return RETURN_ERR;
    }
    return RETURN_OK;
}

INT wifi_setApBeaconRate(INT radioIndex,CHAR *beaconRate)
{
    return 0;
}

INT wifi_getApBeaconRate(INT radioIndex, CHAR *beaconRate)
{
    return 0;
}

INT wifi_setLED(INT radioIndex, BOOL enable)
{
   return 0;
}
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds)
{
   return RETURN_OK;
}
/**********************************************************************************
 *
 *  Wifi Subsystem level function prototypes 
 *
**********************************************************************************/
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)   //RDKB   
{
    if(!output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);

    return RETURN_OK;
}


/* wifi_factoryReset() function */
/**
* @description Clears internal variables to implement a factory reset of the Wi-Fi 
* subsystem. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryReset()
{
    char cmd[MAX_BUF_SIZE];

    /*delete running hostapd conf files*/
    for (int index = 0; index <= 1; index++)
    {
        hapd_reset_cfg(hapd_conf + index);
        snprintf(cmd, sizeof(cmd), "rm -rf %s%d.conf", CONFIG_PREFIX, index);
        system(cmd);
    }
    wifi_dbg_printf("\n[%s]: deleting hostapd conf file %s",__func__,conf_name);
    system("systemctl restart hostapd.service");

    return RETURN_OK;
}

/* wifi_factoryResetRadios() function */
/**
* @description Restore all radio parameters without touching access point parameters. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
*
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadios()
{
    if((RETURN_OK == wifi_factoryResetRadio(0)) && (RETURN_OK == wifi_factoryResetRadio(1)))
        return RETURN_OK;

    return RETURN_ERR;
}


/* wifi_factoryResetRadio() function */
/**
* @description Restore selected radio parameters without touching access point parameters
*
* @param radioIndex - Index of Wi-Fi Radio channel
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadio(int radioIndex) 	//RDKB
{
    char cmd[MAX_CMD_SIZE];
    const char *src;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(radioIndex == 0)
    {
        src = "/etc/hostapd-2G.conf";
    }
    else if(radioIndex == 1)
    {
        src = "/etc/hostapd-5G.conf";
    }
    else
         return RETURN_ERR;

    hapd_reset_cfg(hapd_conf + radioIndex);
    snprintf(cmd, sizeof(cmd), "cp %s %s%d.conf", src, CONFIG_PREFIX, radioIndex);
    system(cmd);

    system("systemctl restart hostapd.service");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* wifi_initRadio() function */
/**
* Description: This function call initializes the specified radio.
*  Implementation specifics may dictate the functionality since 
*  different hardware implementations may have different initilization requirements.
* Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_initRadio(INT radioIndex)
{
    //TODO: Initializes the wifi subsystem (for specified radio)
    return RETURN_OK;
}
void macfilter_init()
{
    char count[4]={'\0'};
    char buf[253]={'\0'};
    char tmp[19]={'\0'};
    int dev_count,block,mac_entry=0;
    char res[4]={'\0'};
    char acl_file_path[64] = {'\0'};
    FILE *fp = NULL;
    int index=0;
    char iface[10]={'\0'};


    sprintf(acl_file_path,"/tmp/mac_filter.sh");

    fp=fopen(acl_file_path,"w+");
    sprintf(buf,"#!/bin/sh \n");
    fprintf(fp,"%s\n",buf);

    system("chmod 0777 /tmp/mac_filter.sh");

    for(index=0;index<=1;index++)
    {
        wifi_hostapdRead(index, "interface", iface, sizeof(iface));
        sprintf(buf,"syscfg get %dcountfilter",index);
        _syscmd(buf,count,sizeof(count));
        mac_entry=atoi(count);

        sprintf(buf,"syscfg get %dblockall",index);
        _syscmd(buf,res,sizeof(res));
        block = atoi(res);

        //Allow only those macs mentioned in ACL
        if(block==1)
        {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);
             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                 sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                 _syscmd(buf,tmp,sizeof(tmp));
                 fprintf(stderr,"MAcs to be Allowed  *%s*  ###########\n",tmp);
                 sprintf(buf,"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",index,iface,tmp);
                 fprintf(fp,"%s\n",buf);
             }
             sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",index,iface,tmp);
             fprintf(fp,"%s\n",buf);
       }

       //Block all the macs mentioned in ACL
       else if(block==2)
       {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);

             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                  sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                  _syscmd(buf,tmp,sizeof(tmp));
                  fprintf(stderr,"MAcs to be blocked  *%s*  ###########\n",tmp);
                  sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",index,iface,tmp);
                  fprintf(fp,"%s\n",buf);
             }
       }
    }
    fclose(fp);
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //RDKB
{
    char interface[MAX_BUF_SIZE]={'\0'};
    char bridge_name[MAX_BUF_SIZE]={'\0'};
    INT len=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //Not intitializing macfilter for Turris-Omnia Platform for now
    //macfilter_init();

    system("/usr/sbin/iw reg set US");
    system("systemctl start hostapd.service");
    sleep(2);//sleep to wait for hostapd to start

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

/* wifi_reset() function */
/**
* Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
*  Implementation specifics may dictate what is actualy reset since 
*  different hardware implementations may have different requirements.
* Parameters : None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_reset()
{
    //TODO: resets the wifi subsystem, deletes all APs
    return RETURN_OK;
}

/* wifi_down() function */
/**
* @description Turns off transmit power for the entire Wifi subsystem, for all radios.
* Implementation specifics may dictate some functionality since 
* different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_down()
{
    //TODO: turns off transmit power for the entire Wifi subsystem, for all radios
    return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/**
* @description This function creates wifi configuration files. The format
* and content of these files are implementation dependent.  This function call is 
* used to trigger this task if necessary. Some implementations may not need this 
* function. If an implementation does not need to create config files the function call can 
* do nothing and return RETURN_OK.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_createInitialConfigFiles()
{
    //TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
    return RETURN_OK;
}

// outputs the country code to a max 64 character string
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, "US");

    return RETURN_OK;
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
    //Set wifi config. Wait for wifi reset to apply
    return RETURN_OK;
}

/**********************************************************************************
 *
 *  Wifi radio level function prototypes
 *
**********************************************************************************/

//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output) //Tr181
{
    if (NULL == output)
        return RETURN_ERR;
    *output = 2;

    return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem 
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
    if (NULL == output)
        return RETURN_ERR;
    *output = MAX_APS;

    return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)      //RDKB
{
    char interface_path[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;

    if (NULL == output_bool)
        return RETURN_ERR;

    *output_bool = FALSE;
    if (!((radioIndex == 0) || (radioIndex == 1)))// Target has two wifi radios
        return RETURN_ERR;

    snprintf(interface_path, sizeof(interface_path), "/sys/class/net/%s%d/address", RADIO_PREFIX, radioIndex);
    fp = fopen(interface_path, "r");
    if(fp)
    {
        *output_bool = TRUE;
        fclose(fp);
    }
    //TODO: check if hostapd with config is running

    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable)
{
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    int apIndex, ret;
    FILE *fp = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(enable==FALSE)
    {
        for(apIndex=radioIndex; apIndex<MAX_APS; apIndex+=2)
        {
            //Detaching %s%d from hostapd daemon
            snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw REMOVE %s%d", AP_PREFIX, apIndex);
            _syscmd(cmd, buf, sizeof(buf));
            if(strncmp(buf, "OK", 2))
                fprintf(stderr, "Could not detach %s%d from hostapd daemon", AP_PREFIX, apIndex);
            snprintf(cmd, sizeof(cmd), "iw %s%d del", AP_PREFIX, apIndex);
            _syscmd(cmd, buf, sizeof(buf));
        }
        snprintf(cmd, sizeof(cmd), "rmmod %s", radioIndex? DRIVER_5GHZ :DRIVER_2GHZ);
        _syscmd(cmd, buf, sizeof(buf));
        if(strlen(buf))
            fprintf(stderr, "Could not remove driver module");
    }
    else
    {
        //Inserting driver for Wifi Radio
        snprintf(cmd, sizeof(cmd), "modprobe %s", radioIndex? DRIVER_5GHZ :DRIVER_2GHZ);
        _syscmd(cmd, buf, sizeof(buf));
        if(strlen(buf))
            fprintf(stderr, "FATAL: Could not insert driver module");
        sleep(1);
        if(radioIndex == 1)//If "wlan0" interface created for 5GHz radio, then need to rename to wlan1
        {
            snprintf(cmd, sizeof(cmd), "/sys/class/net/%s%d/address", RADIO_PREFIX, radioIndex);
	    fp = fopen(cmd, "r");
            if(!fp)
            {
                snprintf(cmd, sizeof(cmd), "ip link set %s0 down", RADIO_PREFIX);
                _syscmd(cmd, buf, sizeof(buf));
                snprintf(cmd, sizeof(cmd), "ip link set %s0 name %s%d", RADIO_PREFIX, RADIO_PREFIX, radioIndex);
                _syscmd(cmd, buf, sizeof(buf));
            }
	    if(fp)
	        fclose(fp);
        }
        for(apIndex=radioIndex; apIndex<MAX_APS; apIndex+=2)
        {
            snprintf(cmd, sizeof(cmd), "iw %s%d interface add %s%d type __ap", RADIO_PREFIX, radioIndex, AP_PREFIX, apIndex);
            ret = _syscmd(cmd, buf, sizeof(buf));
            if ( ret == RETURN_ERR)
            {
                fprintf(stderr, "VAP interface creation failed\n");
                continue;
            }
            snprintf(cmd, sizeof(cmd), "cat %s | grep %s%d | cut -d'=' -f2", VAP_STATUS_FILE, AP_PREFIX, apIndex);
            _syscmd(cmd, buf, sizeof(buf));
            if(*buf == '1')
            {
                snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw ADD bss_config=phy%d:%s%d.conf",
                              radioIndex, CONFIG_PREFIX, apIndex);
                _syscmd(cmd, buf, sizeof(buf));
                if(strncmp(buf, "OK", 2))
                    fprintf(stderr, "Could not detach %s%d from hostapd daemon", AP_PREFIX, apIndex);
            }
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{
    if (NULL == output_bool)
        return RETURN_ERR;

    return wifi_getRadioEnable(radioIndex, output_bool);
}

//Get the Radio Interface name from platform, eg "wlan0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
    if (NULL == output_string || radioIndex>=NUMBER_OF_RADIOS || radioIndex<0)
        return RETURN_ERR;
    snprintf(output_string, 64, "%s%d", RADIO_PREFIX, radioIndex);

    return RETURN_OK;
}

//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) //RDKB
{
    char cmd[MAX_CMD_SIZE] =  {0};
    char buf[MAX_BUF_SIZE] = {0};
    char interface_name[IF_NAME_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    GetInterfaceName(radioIndex, interface_name);

    snprintf(cmd, sizeof(cmd), "iwconfig %s | grep 'Bit Rate' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1,2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    if(strlen(buf) > 0)
        snprintf(output_string, 64, "%s", buf);
    else
    {
        wifi_getRadioOperatingChannelBandwidth(radioIndex,buf);
        if((strcmp(buf,"20MHz") == 0) && (radioIndex == 0))
            strcpy(output_string,"144 Mb/s");
        else if((strcmp(buf,"20MHz") == 0) && (radioIndex == 1))
            strcpy(output_string,"54 Mb/s");
        else if((strcmp(buf,"40MHz") == 0) && (radioIndex == 1))
            strcpy(output_string,"300 Mb/s");
        //TODO: CHECK VALID VALUE
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}
#if 0
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[64];
    char buf[1024];
    int apIndex;

    if (NULL == output_string) 
        return RETURN_ERR;

    apIndex=(radioIndex==0)?0:1;

    snprintf(cmd, sizeof(cmd), "iwconfig %s%d | grep \"Bit Rate\" | cut -d':' -f2 | cut -d' ' -f1,2", AP_PREFIX, apIndex);
    _syscmd(cmd,buf, sizeof(buf));

    snprintf(output_string, 64, "%s", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#endif


//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, (radioIndex == 0)?"2.4GHz":"5GHz");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
        char buf[MAX_BUF_SIZE]={'\0'};
        char str[MAX_BUF_SIZE]={'\0'};
        char cmd[MAX_CMD_SIZE]={'\0'};
        char *ch=NULL;
        char *ch2=NULL;

        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        if (NULL == output_string)
            return RETURN_ERR;


        sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);

   		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
        {
    	    printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
            return RETURN_ERR;
        }
        ch=strchr(buf,'\n');
        *ch='\0';
        ch=strchr(buf,'=');
        if(ch==NULL)
          return RETURN_ERR;


        ch++;

 /* prepend 0 for channel with single digit. for ex, 6 would be 06  */
        strcpy(buf,"0");
       if(strlen(ch) == 1)
           ch=strcat(buf,ch);


       sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);

        if(_syscmd(cmd,str,64) ==  RETURN_ERR)
        {
                wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
                return RETURN_ERR;
        }


        ch2=strchr(str,'\n');
        //replace \n with \0
        *ch2='\0';
        ch2=strchr(str,'=');
        if(ch2==NULL)
        {
        	wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
       		return RETURN_ERR;
        }
        else
         wifi_dbg_printf("%s",ch2+1);


        ch2++;


        sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch);

        memset(buf,'\0',sizeof(buf));
        if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
        {
            wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
            return RETURN_ERR;
        }
        if (strstr(buf,"2.4") != NULL )
            strcpy(output_string,"2.4GHz");
        else if(strstr(buf,"5.") != NULL )
            strcpy(output_string,"5GHz");
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#endif
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, (radioIndex == 0)?"2.4GHz":"5GHz");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char buf[MAX_BUF_SIZE]={'\0'};
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch=NULL;
    char *ch2=NULL;
    char ch1[5]="0";

    sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);

    if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
    {
        printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }

    ch=strchr(buf,'\n');
    *ch='\0';
    ch=strchr(buf,'=');
    if(ch==NULL)
        return RETURN_ERR;
    ch++;

    if(strlen(ch)==1)
    {
        strcat(ch1,ch);

    }
    else
    {
        strcpy(ch1,ch);
    }



    sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);
    if(_syscmd(cmd,str,64) ==  RETURN_ERR)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }


    ch2=strchr(str,'\n');
    //replace \n with \0
    *ch2='\0';
    ch2=strchr(str,'=');
    if(ch2==NULL)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }
    else
        wifi_dbg_printf("%s",ch2+1);
    ch2++;


    sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch1);
    memset(buf,'\0',sizeof(buf));
    if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }


    if(strstr(buf,"2.4")!=NULL)
    {
        strcpy(output_string,"2.4GHz");
    }
    if(strstr(buf,"5.")!=NULL)
    {
        strcpy(output_string,"5GHz");
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
#endif
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
    if (NULL == output_string) 
        return RETURN_ERR;
    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"a,n,ac");

    return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    if (radioIndex == 0) {
        snprintf(output_string, 64, "n");               //"ht" needs to be translated to "n" or others
        *gOnly = FALSE;
        *nOnly = TRUE;
        *acOnly = FALSE;
    } else {
        snprintf(output_string, 64, "ac");              //"vht" needs to be translated to "ac"
        *gOnly = FALSE;
        *nOnly = FALSE;
        *acOnly = FALSE;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char buf[64] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if ((NULL == output_string) || (NULL == gOnly) || (NULL == nOnly) || (NULL == acOnly)) 
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "hw_mode", buf, sizeof(buf));

    wifi_dbg_printf("\nhw_mode=%s\n",buf);
    if (strlen(buf) == 0) 
    {
        wifi_dbg_printf("\nwifi_hostapdRead returned none\n");
        return RETURN_ERR;
    }
    if(strcmp(buf,"g")==0)
    {
        wifi_dbg_printf("\nG\n");
        *gOnly=TRUE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else if(strcmp(buf,"n")==0)
    {
        wifi_dbg_printf("\nN\n");
        *gOnly=FALSE;
        *nOnly=TRUE;
        *acOnly=FALSE;
    }
    else if(strcmp(buf,"ac")==0)
    {
        wifi_dbg_printf("\nac\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=TRUE;
    }
    /* hostapd-5G.conf has "a" as hw_mode */
    else if(strcmp(buf,"a")==0)
    {
        wifi_dbg_printf("\na\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else
        wifi_dbg_printf("\nInvalid Mode %s\n", buf);

    //for a,n mode
    if(radioIndex == 1)
    {
        wifi_hostapdRead(config_file, "ieee80211n", buf, sizeof(buf));
        if(strcmp(buf,"1")==0)
        {
            strncpy(output_string, "n", 1);
            *nOnly=FALSE;
        }
    }

    wifi_dbg_printf("\nReturning from getRadioStandard\n");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
#endif
}

//Set the radio operating mode, and pure mode flag. 
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s_%s_%d_%d:%d\n",__func__,channelMode,nOnlyFlag,gOnlyFlag,__LINE__);  
    if (strcmp (channelMode,"11A") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11a (5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11n-20MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11ac-20MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT80") == 0)
    {
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"80MHz");
        printf("\nChannel Mode is 802.11ac-80MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT160") == 0)
    {
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"160MHz");
        printf("\nChannel Mode is 802.11ac-160MHz(5GHz)\n");
    }      
    else if (strcmp (channelMode,"11B") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11b(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11G") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11g(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11n-20MHz(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
    }
    else 
    {
        return RETURN_ERR;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
    if (NULL == output_string) 
        return RETURN_ERR;
    //TODO:read this from iw phy phyX info |grep MHz
    snprintf(output_string, 64, (radioIndex == 0)?"1,2,3,4,5,6,7,8,9,10,11":"36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140");
#if 0
    char IFName[50] ={0};
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    int count = 0;
    if (NULL == output_string)
        return RETURN_ERR;

    //snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
    if(radioIndex == 0)
    {
        GetInterfaceName(IFName,"/nvram/hostapd0.conf");
        sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
    }
    else if(radioIndex == 1)
    {
        GetInterfaceName(IFName,"/nvram/hostapd1.conf");
        sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep '5\\.[1-9]' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
    }
    _syscmd(cmd, buf, sizeof(buf));
    if(strlen(buf) > 0)
        strcpy(output_string,buf);
    else
        strcpy(output_string,"0");
#endif
    return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 256, (radioIndex == 0)?"1,6,11":"36,40");
#if 0
    char IFName[50] ={0};
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    if (NULL == output_string)
        return RETURN_ERR;

    //	snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
    if(radioIndex == 0)
    {
        GetInterfaceName(IFName, "/nvram/hostapd0.conf");
        sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
    }
    else if(radioIndex == 1)
    {
        GetInterfaceName(IFName, "/nvram/hostapd1.conf");
        sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 5'\\.[1-9]' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 |tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
    }
    _syscmd(cmd,buf, sizeof(buf));
    if(strlen(buf) > 0)
        strcpy(output_string,buf);
    else
        strcpy(output_string,"0");
#endif
    return RETURN_OK;
}

//Get the running channel number 
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)	//RDKB
{
    char cmd[1024] = {0}, buf[5] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_ulong)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd),
        "ls -1 /sys/class/net/%s%d/device/ieee80211/phy*/device/net/ | "
        "xargs -I {} iw dev {} info | grep channel | head -n1 | "
        "cut -d ' ' -f2", RADIO_PREFIX, radioIndex);
    _syscmd(cmd, buf, sizeof(buf));

    *output_ulong = (strlen(buf) >= 1)? atol(buf): 0;
    if (*output_ulong <= 0) {
        *output_ulong = 0;
        return RETURN_ERR;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}


INT wifi_getApChannel(INT apIndex,ULONG *output_ulong) //RDKB
{
    char cmd[1024] = {0}, buf[5] = {0};
    char interface_name[50] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_ulong)
        return RETURN_ERR;

    wifi_getApName(apIndex,interface_name);
    snprintf(cmd, sizeof(cmd), "iw dev %s info |grep channel | cut -d ' ' -f2",interface_name);
    _syscmd(cmd,buf,sizeof(buf));
    *output_ulong = (strlen(buf) >= 1)? atol(buf): 0;
    if (*output_ulong == 0) {
        return RETURN_ERR;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Storing the previous channel value
INT wifi_storeprevchanval(INT radioIndex)
{
    char buf[256] = {0};
    char output[4]={'\0'};
    wifi_hostapdRead(radioIndex, "channel", output, sizeof(output));
    if(radioIndex == 0)
        sprintf(buf,"%s%s%s","echo ",output," > /var/prevchanval2G_AutoChannelEnable");
    else if(radioIndex == 1)
        sprintf(buf,"%s%s%s","echo ",output," > /var/prevchanval5G_AutoChannelEnable");
    system(buf);
    Radio_flag = FALSE;
    return RETURN_OK;
}

//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char str_channel[4]={'\0'};
    struct params list;

    list.name = "channel";

    if(Radio_flag == TRUE)
        wifi_storeprevchanval(radioIndex);  //for autochannel

    if(radioIndex == 0)
    {
        switch(channel)
        {
            case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12:
                sprintf(str_channel,"%ld", channel);
                list.value = str_channel;
                break;
            default:
                return RETURN_ERR;
        }
    }
    else if(radioIndex == 1)
    {
        switch(channel)
        {
            case 36: case 40: case 44: case 48: case 52: case 56: case 60: case 64: case 144: case 149: case 153: case 157: case 161: case 165: case 169:
                sprintf(str_channel,"%ld", channel);
                list.value = str_channel;
                break;
            default:
                return RETURN_ERR;
        }
    }

    for(int i=0; i<=MAX_APS/NUMBER_OF_RADIOS;i++)
    {
        wifi_hostapdWrite(radioIndex+(2*i), &list, 1);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
 }

INT wifi_setRadioCenterChannel(INT radioIndex, ULONG channel)
{
    struct params list;
    char str_idx[16];

    list.name = "vht_oper_centr_freq_seg0_idx";
    snprintf(str_idx, sizeof(str_idx), "%d", channel);
    list.value = str_idx;

    for(int i=0; i<=MAX_APS/NUMBER_OF_RADIOS; i++)
    {
        wifi_hostapdWrite(radioIndex+(2*i), &list, 1);
    }

    return RETURN_OK;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
    //Set to wifi config only. Wait for wifi reset to apply.
    char buf[256] = {0};
    char str_channel[256] = {0};
    int count = 0;
    ULONG Value = 0;
    FILE *fp = NULL;
    if(enable == TRUE)
    {
        if(radioIndex == 0)
        {
            //	_syscmd("cat /var/prevchanval2G_AutoChannelEnable", buf, sizeof(buf));
            fp = fopen("/var/prevchanval2G_AutoChannelEnable","r");
        }
        else if(radioIndex == 1)
        {
            //	_syscmd("cat /var/prevchanval5G_AutoChannelEnable", buf, sizeof(buf));
            fp = fopen("/var/prevchanval5G_AutoChannelEnable","r");
        }
        if(fp == NULL) //first time boot-up
        {
            if(radioIndex == 0)
                Value = 6;
            else if(radioIndex == 1)
                Value = 36;
        }
        else
        {
            if(fgets(buf,sizeof(buf),fp) != NULL)
            {
                for(count = 0;buf[count]!='\n';count++)
                    str_channel[count] = buf[count];
                str_channel[count] = '\0';
                Value = atol(str_channel);
                printf("%sValue is %ld \n",__FUNCTION__,Value);
                pclose(fp);
            }
        }
        Radio_flag = FALSE;//for storing previous channel value
        wifi_setRadioChannel(radioIndex,Value);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool) 	//RDKB
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//RDKB
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)            //RDKB
{
    //Set to wifi config only. Wait for wifi reset to apply.
    return RETURN_OK;
}

INT wifi_setApEnableOnLine(ULONG wlanIndex,BOOL enable)
{
   return RETURN_OK;
}

INT wifi_factoryResetAP(int apIndex)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //factory reset is not done for now on Turris
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//To set Band Steering AP group
//To-do
INT wifi_setBandSteeringApGroup(char *ApGroup)
{
    return RETURN_OK;
}

INT wifi_setApDTIMInterval(INT apIndex, INT dtimInterval)
{
   return RETURN_OK;
}

//Check if the driver support the Dfs
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool) //Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//RDKB
{
    if (NULL == output_pool) 
        return RETURN_ERR;
    if (radioIndex==1)
        return RETURN_OK;//TODO need to handle for 5GHz band, i think 
    snprintf(output_pool, 256, "1,2,3,4,5,6,7,8,9,10,11");

    return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//RDKB
{
    //Set to wifi config. And apply instantly.
    return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
    if (NULL == output_interval_seconds || NULL == output_dwell_milliseconds) 
        return RETURN_ERR;
    *output_interval_seconds=1800;
    *output_dwell_milliseconds=40;

    return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
    //Set to wifi config. And apply instantly.
    return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool = FALSE;

    return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
    return RETURN_ERR;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;		//not support

    return RETURN_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
    if (NULL == output_ulong) 
        return RETURN_ERR;
    *output_ulong=300;

    return RETURN_OK;
}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
    return RETURN_ERR;
}

//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
    if (NULL == output_string)
        return RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[1024] = {0}, buf[64] = {0};
    int ret = 0, len=0;

    snprintf(cmd, sizeof(cmd),
        "ls -1 /sys/class/net/%s%d/device/ieee80211/phy*/device/net/ | "
        "xargs -I {} iw dev {} info | grep width | head -n1 | "
        "cut -d ' ' -f6", RADIO_PREFIX, radioIndex);

    ret = _syscmd(cmd, buf, sizeof(buf));
    len = strlen(buf);
    if((ret != 0) || (len == 0))
    {
         WIFI_ENTRY_EXIT_DEBUG("failed with Command %s %s:%d\n",cmd,__func__, __LINE__);
         return RETURN_ERR;
    }

    buf[len-1] = '\0';
    snprintf(output_string, 64, "%sMHz", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

#if 0
    //TODO: revisit below implementation
    char output_buf[8]={0};
    char bw_value[10];
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file, "vht_oper_chwidth", output_buf, sizeof(output_buf));
    readBandWidth(radioIndex,bw_value);

    if(strstr (output_buf,"0") != NULL )
    {
        strcpy(output_string,bw_value);
    }
    else if (strstr (output_buf,"1") != NULL)
    {
        strcpy(output_string,"80MHz");
    }
    else if (strstr (output_buf,"2") != NULL)
    {
        strcpy(output_string,"160MHz");
    }
    else if (strstr (output_buf,"3") != NULL)
    {
        strcpy(output_string,"80+80");
    }
    else
    {
        strcpy(output_string,"Auto");
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
#endif

    return RETURN_OK;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181	//AP only
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params[4];
    struct params *pptr = params;

    if(NULL == output_string)
        return RETURN_ERR;

    pptr->name = "vht_oper_chwidth";
    if(strcmp(output_string,"20MHz") == 0)  // This piece of code only support for wifi hal api's validation
        pptr->value="0";
    else if(strcmp(output_string,"40MHz") == 0)
        pptr->value="0";
    else if(strcmp(output_string,"80MHz") == 0)
        pptr->value="1";
    else if(strcmp(output_string,"160MHz") == 0)
        pptr->value="2";
    else if(strcmp(output_string,"80+80") == 0)
        pptr->value="3";
    else
    {
        printf("Invalid Bandwidth \n");
        return RETURN_ERR;
    }

    pptr++; // added vht_oper_chwidth

    if(radioIndex == 1)
    {
        pptr->name= "ieee80211n";
        if(strcmp(output_string,"20MHz") == 0)
            pptr->value="0";
        else if(strcmp(output_string,"40MHz") == 0)
            pptr->value="1";
        else if(strcmp(output_string,"80MHz") == 0)
            pptr->value="1";
        else 
            pptr->value="0";

        pptr++; // added ieee80211n

        pptr->name="ieee80211ac";
        if(strcmp(output_string,"80MHz") == 0)
            pptr->value="1";
        else
            pptr->value="0";
        pptr++;
    }

    for(int i=0; i<=MAX_APS/NUMBER_OF_RADIOS; i++)
    {
       wifi_hostapdWrite(radioIndex+(2*i), params, (pptr - params));
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Getting current radio extension channel
INT wifi_halgetRadioExtChannel(CHAR *file,CHAR *Value)
{
    CHAR buf[150] = {0};
    CHAR cmd[150] = {0};
    sprintf(cmd,"%s%s%s","cat ",file," | grep -w ht_capab=");
    _syscmd(cmd, buf, sizeof(buf));
    if(NULL != strstr(buf,"HT40+"))
        strcpy(Value,"AboveControlChannel");
    else if(NULL != strstr(buf,"HT40-"))
        strcpy(Value,"BelowControlChannel");
    return RETURN_OK;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
    if (NULL == output_string)
        return RETURN_ERR;

    snprintf(output_string, 64, (radioIndex==0)?"":"BelowControlChannel");
#if 0
    CHAR Value[100] = {0};
    if (NULL == output_string)
        return RETURN_ERR;
    if(radioIndex == 0)
        strcpy(Value,"Auto"); //so far rpi(2G) supports upto 150Mbps (i,e 20MHZ)
    else if(radioIndex == 1)//so far rpi(5G) supports upto 300mbps (i,e 20MHz/40MHz)
    {
        wifi_getRadioOperatingChannelBandwidth(radioIndex,Value);
        if(strcmp(Value,"40MHz") == 0)
            wifi_halgetRadioExtChannel("/nvram/hostapd1.conf",Value);
        else
            strcpy(Value,"Auto");
    }
    strcpy(output_string,Value);
#endif

    return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{        
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char ext_channel[127]={'\0'};

    params.name = "ht_capab";

    if(radioIndex == 0)
    {
        if(NULL!= strstr(string,"Above"))
            strcpy(ext_channel, HOSTAPD_HT_CAPAB_40 "[HT40+]");
        else if(NULL!= strstr(string,"Below"))
            strcpy(ext_channel, HOSTAPD_HT_CAPAB_40 "[HT40-]");
        else
            strcpy(ext_channel, HOSTAPD_HT_CAPAB_20);
    }
    else if(radioIndex  == 1)
    {
        if(NULL!= strstr(string,"Above"))
            strcpy(ext_channel, HOSTAPD_HT_CAPAB_40 "[HT40+]");
        else if(NULL!= strstr(string,"Below"))
            strcpy(ext_channel, HOSTAPD_HT_CAPAB_40 "[HT40-]");
	else
	    strcpy(ext_channel, HOSTAPD_HT_CAPAB_20);
    }

    params.value = ext_channel;
    for(int i=0; i<=MAX_APS/NUMBER_OF_RADIOS; i++)
    {
        wifi_hostapdWrite(radioIndex+(2*i), &params, 1);
    }

    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the guard interval value. eg "400nsec" or "800nsec"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
    //save config and apply instantly
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, (radioIndex == 0) ? "400nsec" : "400nsec");

    return RETURN_OK;
}

//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
    //Apply setting instantly
    return RETURN_ERR;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
    if (NULL == output_int) 
        return RETURN_ERR;
    *output_int=(radioIndex==0)?1:3;

    return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
    return RETURN_ERR;
}

//Get supported Transmit Power list, eg : "0,25,50,75,100"
//The output_list is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) //Tr181
{
        if (NULL == output_list)
                return RETURN_ERR;
        snprintf(output_list, 64,"0,25,50,75,100");
        return RETURN_OK;
}

//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
    char cmd[128]={0};
    char buf[256]={0};
    INT apIndex;
    //save config and apply instantly

    if (NULL == output_ulong) 
        return RETURN_ERR;

    //zqiu:TODO:save config
    apIndex = (radioIndex==0) ?0 :1;

    snprintf(cmd, sizeof(cmd),  "iwlist %s%d txpower | grep Tx-Power | cut -d'=' -f2", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    *output_ulong = atol(buf);

    return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
    char cmd[128]={0};
    char buf[256]={0};
    INT apIndex;

    snprintf(cmd, sizeof(cmd),  "iwconfig %s%d txpower %lu", AP_PREFIX, radioIndex, TransmitPower);
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
    if (NULL == Supported) 
        return RETURN_ERR;
    *Supported = FALSE;

    return RETURN_OK;
}

//Get 80211h feature enable
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) //Tr181
{
    if (NULL == enable)
        return RETURN_ERR;
    *enable = FALSE;

    return RETURN_OK;
}

//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
    return RETURN_ERR;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
    if (NULL == output)
        return RETURN_ERR;
    *output=100;

    return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
    if (NULL == output)
        return RETURN_ERR;
    *output = -99;

    return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
    return RETURN_ERR;
}


//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
    if (NULL == output)
        return RETURN_ERR;
    *output = 100;

    return RETURN_OK;
}
 
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
    return RETURN_ERR;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
    if (NULL == output)
        return RETURN_ERR;
    snprintf(output, 64, (radioIndex == 0) ? "1,2" : "1.5,150");
#if 0
    //TODO: need to revisit below implementation
    char *temp;
    char temp_output[128];
    char temp_TransmitRates[512];
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"basic_rates",output,64);

    strcpy(temp_TransmitRates,output);
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        temp[strlen(temp)-1]=0;
        if((temp[0]=='5') && (temp[1]=='\0'))
        {
            temp="5.5";
        }
        strcat(temp_output,temp);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output,",");
        }
    }
    strcpy(output,temp_output);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
#endif
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
    char *temp;
    char temp1[128];
    char temp_output[128];
    char temp_TransmitRates[128];
    char set[128];
    char sub_set[128];
    int set_count=0,subset_count=0;
    int set_index=0,subset_index=0;
    char *token;
    int flag=0, i=0;
    struct params params={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == TransmitRates)
        return RETURN_ERR;
    strcpy(sub_set,TransmitRates);

    //Allow only supported Data transmit rate to be set
    wifi_getRadioSupportedDataTransmitRates(radioIndex,set);
    token = strtok(sub_set,",");
    while( token != NULL  )  /* split the basic rate to be set, by comma */
    {
        sub_set[subset_count]=atoi(token);
        subset_count++;
        token=strtok(NULL,",");
    }
    token=strtok(set,",");
    while(token!=NULL)   /* split the supported rate by comma */
    {
        set[set_count]=atoi(token);
        set_count++;
        token=strtok(NULL,",");
    }
    for(subset_index=0;subset_index < subset_count;subset_index++) /* Compare each element of subset and set */
    {
        for(set_index=0;set_index < set_count;set_index++)
        {
            flag=0;
            if(sub_set[subset_index]==set[set_index])
                break;
            else
                flag=1; /* No match found */
        }
        if(flag==1)
            return RETURN_ERR; //If value not found return Error
    }
    strcpy(temp_TransmitRates,TransmitRates);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
    //if (((temp_TransmitRates[i]>=48) && (temp_TransmitRates[i]<=57)) | (temp_TransmitRates[i]==32))
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) | (temp_TransmitRates[i]==' ') | (temp_TransmitRates[i]=='.') | (temp_TransmitRates[i]==','))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates,",");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(radioIndex==1)
        {
            if((strcmp(temp,"1")==0) | (strcmp(temp,"2")==0) | (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }

        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL,",");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(TransmitRates,temp_output);

    params.name= "basic_rates";
    params.value =TransmitRates;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("\nparams.value=%s\n",params.value);
    wifi_dbg_printf("\n******************Transmit rates=%s\n",TransmitRates);
    wifi_hostapdWrite(radioIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//passing the hostapd configuration file and get the virtual interface of xfinity(2g)
INT GetInterfaceName_virtualInterfaceName_2G(char interface_name[50])
{
    int res;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    res = wifi_hostapdRead(AP_IDX_2G_PRIVATE, "bss", interface_name, 50 /*IF_NAME_SIZE*/ );
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return res;
}

INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    output_struct->radio_BytesSent = 0;
    output_struct->radio_BytesReceived = 0;
    output_struct->radio_PacketsSent = 0;
    output_struct->radio_PacketsReceived = 0;
    output_struct->radio_ErrorsSent = 0;
    output_struct->radio_ErrorsReceived = 0;
    output_struct->radio_DiscardPacketsSent = 0;
    output_struct->radio_DiscardPacketsReceived = 0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}


INT wifi_halGetIfStats(char *ifname, wifi_radioTrafficStats2_t *pStats)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    CHAR buf[MAX_CMD_SIZE] = {0};
    CHAR Value[MAX_BUF_SIZE] = {0};
    FILE *fp = NULL;

    if (ifname == NULL || strlen(ifname) <= 1)
        return RETURN_OK;

    snprintf(buf, sizeof(buf), "ifconfig -a %s > /tmp/Radio_Stats.txt", ifname);
    system(buf);

    fp = fopen("/tmp/Radio_Stats.txt", "r");
    if(fp == NULL)
    {
        printf("/tmp/Radio_Stats.txt not exists \n");
        return RETURN_ERR;
    }
    fclose(fp);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_PacketsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_PacketsSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_BytesReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_BytesSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_ErrorsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_ErrorsSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_DiscardPacketsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_DiscardPacketsSent = strtoul(Value, NULL, 10);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT GetIfacestatus(CHAR *interface_name, CHAR *status)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    CHAR buf[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;
    INT count = 0;

    if (interface_name != NULL && (strlen(interface_name) > 1) && status != NULL)
    {
        sprintf(buf, "%s%s%s%s%s", "ifconfig -a ", interface_name, " | grep ", interface_name, " | wc -l");
        File_Reading(buf, status);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{

#if 0	
    //ifconfig radio_x	
    output_struct->radio_BytesSent=250;	//The total number of bytes transmitted out of the interface, including framing characters.
    output_struct->radio_BytesReceived=168;	//The total number of bytes received on the interface, including framing characters.
    output_struct->radio_PacketsSent=25;	//The total number of packets transmitted out of the interface.
    output_struct->radio_PacketsReceived=20; //The total number of packets received on the interface.

    output_struct->radio_ErrorsSent=0;	//The total number of outbound packets that could not be transmitted because of errors.
    output_struct->radio_ErrorsReceived=0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->radio_DiscardPacketsSent=0; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->radio_DiscardPacketsReceived=0; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.

    output_struct->radio_PLCPErrorCount=0;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.	
    output_struct->radio_FCSErrorCount=0;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
    output_struct->radio_InvalidMACCount=0;	//The number of packets that were received with a detected invalid MAC header error.
    output_struct->radio_PacketsOtherReceived=0;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
    output_struct->radio_NoiseFloor=-99; 	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
    output_struct->radio_ChannelUtilization=35; //Percentage of time the channel was occupied by the radios own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
    output_struct->radio_ActivityFactor=2; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_CarrierSenseThreshold_Exceeded=20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_RetransmissionMetirc=0; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

    output_struct->radio_MaximumNoiseFloorOnChannel=-1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
    output_struct->radio_MinimumNoiseFloorOnChannel=-1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_MedianNoiseFloorOnChannel=-1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_StatisticsStartTime=0; 	    //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

    return RETURN_OK;
#endif

    CHAR private_interface_name[IF_NAME_SIZE] = {0};
    CHAR private_interface_status[MAX_BUF_SIZE] = {0};
    CHAR public_interface_name[IF_NAME_SIZE] = {0};
    CHAR public_interface_status[MAX_BUF_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    wifi_radioTrafficStats2_t private_radioTrafficStats = {0}, public_radioTrafficStats = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    if (radioIndex == 0) //2.4GHz ?
    {

        GetInterfaceName(AP_IDX_2G_PRIVATE, private_interface_name);
        GetIfacestatus(private_interface_name, private_interface_status);

        // First check legacy configuration using 'bss=name'
        if (RETURN_OK != GetInterfaceName_virtualInterfaceName_2G(public_interface_name))
        {
            // Legacy form does not exist, get name using common approach
            GetInterfaceName(AP_IDX_2G_PUBLIC, public_interface_name);
        }
        GetIfacestatus(public_interface_name, public_interface_status);

        if (strcmp(private_interface_status, "1") == 0)
            wifi_halGetIfStats(private_interface_name, &private_radioTrafficStats);
        else
            wifi_halGetIfStatsNull(&private_radioTrafficStats);

        if (strcmp(public_interface_status, "1") == 0)
            wifi_halGetIfStats(public_interface_name, &public_radioTrafficStats);
        else
            wifi_halGetIfStatsNull(&public_radioTrafficStats);
    }
    else if (radioIndex == 1) //5GHz ?
    {
        GetInterfaceName(AP_IDX_5G_PRIVATE, private_interface_name);
        GetIfacestatus(private_interface_name, private_interface_status);

        GetInterfaceName(AP_IDX_5G_PUBLIC, public_interface_name);
        GetIfacestatus(public_interface_name, public_interface_status);

        if (strcmp(private_interface_status, "1") == 0)
            wifi_halGetIfStats(private_interface_name, &private_radioTrafficStats);
        else
            wifi_halGetIfStatsNull(&private_radioTrafficStats);

        if (strcmp(public_interface_status, "1") == 0)
            wifi_halGetIfStats(public_interface_name, &public_radioTrafficStats);
        else
            wifi_halGetIfStatsNull(&public_radioTrafficStats);
    }

    output_struct->radio_BytesSent = private_radioTrafficStats.radio_BytesSent + public_radioTrafficStats.radio_BytesSent;
    output_struct->radio_BytesReceived = private_radioTrafficStats.radio_BytesReceived + public_radioTrafficStats.radio_BytesReceived;
    output_struct->radio_PacketsSent = private_radioTrafficStats.radio_PacketsSent + public_radioTrafficStats.radio_PacketsSent;
    output_struct->radio_PacketsReceived = private_radioTrafficStats.radio_PacketsReceived + public_radioTrafficStats.radio_PacketsReceived;
    output_struct->radio_ErrorsSent = private_radioTrafficStats.radio_ErrorsSent + public_radioTrafficStats.radio_ErrorsSent;
    output_struct->radio_ErrorsReceived = private_radioTrafficStats.radio_ErrorsReceived + public_radioTrafficStats.radio_ErrorsReceived;
    output_struct->radio_DiscardPacketsSent = private_radioTrafficStats.radio_DiscardPacketsSent + public_radioTrafficStats.radio_DiscardPacketsSent;
    output_struct->radio_DiscardPacketsReceived = private_radioTrafficStats.radio_DiscardPacketsReceived + public_radioTrafficStats.radio_DiscardPacketsReceived;

    output_struct->radio_PLCPErrorCount = 0;				  //The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
    output_struct->radio_FCSErrorCount = 0;					  //The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
    output_struct->radio_InvalidMACCount = 0;				  //The number of packets that were received with a detected invalid MAC header error.
    output_struct->radio_PacketsOtherReceived = 0;			  //The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
    output_struct->radio_NoiseFloor = -99;					  //The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
    output_struct->radio_ChannelUtilization = 35;			  //Percentage of time the channel was occupied by the radio\92s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
    output_struct->radio_ActivityFactor = 2;				  //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_CarrierSenseThreshold_Exceeded = 20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_RetransmissionMetirc = 0;			  //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

    output_struct->radio_MaximumNoiseFloorOnChannel = -1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
    output_struct->radio_MinimumNoiseFloorOnChannel = -1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_MedianNoiseFloorOnChannel = -1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_StatisticsStartTime = 0;		  //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

    return RETURN_OK;
}

//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) //Tr181
{
    //zqiu:  If the RadioTrafficStats process running, and the new value is different from old value, the process needs to be reset. The Statistics date, such as MaximumNoiseFloorOnChannel, MinimumNoiseFloorOnChannel and MedianNoiseFloorOnChannel need to be reset. And the "StatisticsStartTime" must be reset to the current time. Units in Seconds
    //       Else, save the MeasuringRate and MeasuringInterval for future usage

    return RETURN_OK;
}

//To start or stop RadioTrafficStats
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable)
{
    //zqiu:  If the RadioTrafficStats process running
    //          	if(enable)
    //					return RETURN_OK.
    //				else
    //					Stop RadioTrafficStats process
    //       Else 
    //				if(enable)
    //					Start RadioTrafficStats process with MeasuringRate and MeasuringInterval, and reset "StatisticsStartTime" to the current time, Units in Seconds
    //				else
    //					return RETURN_OK.

    return RETURN_OK;
}

//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
    //zqiu: Please ignor signalIndex.
    if (NULL == SignalLevel) 
        return RETURN_ERR;
    *SignalLevel=(radioIndex==0)?-19:-19;

    return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex)
{
    return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex)
{
    if (NULL == radioIndex) 
        return RETURN_ERR;
    *radioIndex=ssidIndex%2;

    return RETURN_OK;
}

//Device.WiFi.SSID.{i}.Enable
//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;

    //For this target, mapping SSID Index 13 & 14 to 2 & 3 respectively.
    if(ssidIndex==13 || ssidIndex==14) ssidIndex -= 11;
    return wifi_getApEnable(ssidIndex, output_bool);
}

//Device.WiFi.SSID.{i}.Enable
//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
    //For this target, mapping SSID Index 13 & 14 to 2 & 3 respectively.
    if(ssidIndex==13 || ssidIndex==14) ssidIndex -= 11;
    return wifi_setApEnable(ssidIndex, enable);
}

//Device.WiFi.SSID.{i}.Status
//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
    char cmd[MAX_CMD_SIZE]={0};
    char buf[MAX_BUF_SIZE]={0};
    BOOL output_bool;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;
    //For this target, mapping SSID Index 13 & 14 to 2 & 3 respectively.
    if(ssidIndex==13 || ssidIndex==14) ssidIndex -= 11;

    wifi_getApEnable(ssidIndex,&output_bool);
    snprintf(output_string, 32, output_bool==1?"Enabled":"Disabled");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_getSSIDName(INT apIndex, CHAR *output)
{

    if (NULL == output) 
        return RETURN_ERR;

    wifi_hostapdRead(apIndex,"ssid",output,32);

    wifi_dbg_printf("\n[%s]: SSID Name is : %s",__func__,output);
    return RETURN_OK;
}

// Set a max 32 byte string and sets an internal variable to the SSID name          
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    struct params params;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == ssid_string || strlen(ssid_string) >= 32 || strlen(ssid_string) == 0 )
        return RETURN_ERR;

    params.name = "ssid";
    params.value = ssid_string;
    wifi_hostapdWrite(apIndex, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Get the BSSID
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
    char cmd[MAX_CMD_SIZE]="";

    if (NULL == output_string)
        return RETURN_ERR;

    if(ssidIndex >= 0 && ssidIndex < MAX_APS)
    {
        snprintf(cmd, sizeof(cmd), "iw dev %s%d info |grep addr | awk '{printf $2}'", AP_PREFIX, ssidIndex);
        _syscmd(cmd, output_string, 64);
        return RETURN_OK;
    }
    strncpy(output_string, "\0", 1);

    return RETURN_ERR;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
    wifi_getBaseBSSID(ssidIndex,output_string);
    return RETURN_OK;
}

//Get the basic SSID traffic static info
//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
    BOOL status = false;
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    int apIndex, ret;
    int radioIndex = ssidIndex % NUMBER_OF_RADIOS;

    wifi_getApEnable(ssidIndex,&status);
    // Do not apply when ssid index is disabled
    if (status == false)
        return RETURN_OK;

    /* Doing full remove and add for ssid Index
     * Not all hostapd options are supported with reload
     * for example macaddr_acl
     */
    if(wifi_setApEnable(ssidIndex,false) != RETURN_OK)
           return RETURN_ERR;

    ret = wifi_setApEnable(ssidIndex,true);

    /* Workaround for hostapd issue with multiple bss definitions
     * when first created interface will be removed
     * then all vaps other vaps on same phy are removed
     * after calling setApEnable to false readd all enabled vaps */
    for(int i=0; i < MAX_APS/NUMBER_OF_RADIOS; i++) {
       apIndex = 2*i+radioIndex;
        snprintf(cmd, sizeof(cmd), "cat %s | grep %s%d | cut -d'=' -f2", VAP_STATUS_FILE, AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
        if(*buf == '1')
               wifi_setApEnable(apIndex, true);
    }

    return ret;
}

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181	
{
    INT status = RETURN_ERR;
    UINT index;
    wifi_neighbor_ap2_t *pt=NULL;
    char cmd[128]={0};
    char buf[8192]={0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(cmd, "iwlist %s%d scan",AP_PREFIX,(radioIndex==0)?0:1);	//suppose ap0 mapping to radio0
    _syscmd(cmd, buf, sizeof(buf));


    *output_array_size=2;
    //zqiu: HAL alloc the array and return to caller. Caller response to free it.
    *neighbor_ap_array=(wifi_neighbor_ap2_t *)calloc(sizeof(wifi_neighbor_ap2_t), *output_array_size);
    for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
        strcpy(pt->ap_SSID,"");
        strcpy(pt->ap_BSSID,"");
        strcpy(pt->ap_Mode,"");
        pt->ap_Channel=1;
        pt->ap_SignalStrength=0;
        strcpy(pt->ap_SecurityModeEnabled,"");
        strcpy(pt->ap_EncryptionMode,"");
        strcpy(pt->ap_OperatingFrequencyBand,"");
        strcpy(pt->ap_SupportedStandards,"");
        strcpy(pt->ap_OperatingStandards,"");
        strcpy(pt->ap_OperatingChannelBandwidth,"");
        pt->ap_BeaconPeriod=1;
        pt->ap_Noise=0;
        strcpy(pt->ap_BasicDataTransferRates,"");
        strcpy(pt->ap_SupportedDataTransferRates,"");
        pt->ap_DTIMPeriod=1;
        pt->ap_ChannelUtilization=0;
    }

    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return status;
}

//>> Deprecated: used for old RDKB code.
INT wifi_getRadioWifiTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
    INT status = RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    output_struct->wifi_PLCPErrorCount = 0;
    output_struct->wifi_FCSErrorCount = 0;
    output_struct->wifi_InvalidMACCount = 0;
    output_struct->wifi_PacketsOtherReceived = 0;
    output_struct->wifi_Noise = 0;
    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return status;
}

INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct)
{
    char cmd[128];
    char buf[1280];
    char *pos = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

    snprintf(cmd, sizeof(cmd), "ifconfig %s%d", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    pos = buf;
    if ((pos = strstr(pos, "RX packets:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_PacketsReceived = atoi(pos+strlen("RX packets:"));

    if ((pos = strstr(pos, "TX packets:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_PacketsSent = atoi(pos+strlen("TX packets:"));

    if ((pos = strstr(pos, "RX bytes:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_BytesReceived = atoi(pos+strlen("RX bytes:"));

    if ((pos = strstr(pos, "TX bytes:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_BytesSent = atoi(pos+strlen("TX bytes:"));

    sprintf(cmd, "wlanconfig %s%d list sta | grep -v HTCAP | wc -l", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    sscanf(buf, "%lu", &output_struct->wifi_Associations);

#if 0
    //TODO: need to revisit below implementation
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char interface_name[MAX_BUF_SIZE] = {0};
    char interface_status[MAX_BUF_SIZE] = {0};
    char Value[MAX_BUF_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;

    if (NULL == output_struct) {
        return RETURN_ERR;
    }

    memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

    if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
    {
        if(apIndex == 0) //private_wifi for 2.4G
        {
            GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
        }
        else if(apIndex == 1) //private_wifi for 5G
        {
            GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
        }
        else if(apIndex == 4) //public_wifi for 2.4G
        {
            sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
            if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
            {
                return RETURN_ERR;
            }
            if(buf[0] == '#')//tp-link
                GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
            else//tenda
                GetInterfaceName_virtualInterfaceName_2G(interface_name);
        }
        else if(apIndex == 5) //public_wifi for 5G
        {
            GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
        }

        GetIfacestatus(interface_name, interface_status);

        if(0 != strcmp(interface_status, "1"))
            return RETURN_ERR;

        snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
        system(cmd);

        fp = fopen("/tmp/SSID_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/SSID_Stats.txt not exists \n");
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_PacketsReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_PacketsSent = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_BytesReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_BytesSent = strtoul(Value, NULL, 10);

        /* There is no specific parameter from caller to associate the value wifi_Associations */
        //sprintf(cmd, "iw dev %s station dump | grep Station | wc -l", interface_name);
        //_syscmd(cmd, buf, sizeof(buf));
        //sscanf(buf,"%lu", &output_struct->wifi_Associations);
    }
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
    char interface_name[IF_NAME_SIZE] = {0};
    char interface_status[MAX_BUF_SIZE] = {0};
    char Value[MAX_BUF_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    memset(output_struct, 0, sizeof(wifi_trafficStats_t));

    if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
    {
        if(apIndex == 0) //private_wifi for 2.4G
        {
            GetInterfaceName(apIndex, interface_name);
        }
        else if(apIndex == 1) //private_wifi for 5G
        {
            GetInterfaceName(apIndex, interface_name);
        }
        else if(apIndex == 4) //public_wifi for 2.4G
        {
            if (RETURN_OK != GetInterfaceName_virtualInterfaceName_2G(interface_name))
            {
                GetInterfaceName(apIndex, interface_name);
            }
	}
        else if(apIndex == 5) //public_wifi for 5G
        {
            GetInterfaceName(apIndex, interface_name);
        }

        GetIfacestatus(interface_name, interface_status);

        if(0 != strcmp(interface_status, "1"))
            return RETURN_ERR;

        snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
        system(cmd);

        fp = fopen("/tmp/SSID_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/SSID_Stats.txt not exists \n");
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_ErrorsReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_ErrorsSent = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_DiscardedPacketsReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_DiscardedPacketsSent = strtoul(Value, NULL, 10);
    }

    output_struct->wifi_UnicastPacketsSent = 0;
    output_struct->wifi_UnicastPacketsReceived = 0;
    output_struct->wifi_MulticastPacketsSent = 0;
    output_struct->wifi_MulticastPacketsReceived = 0;
    output_struct->wifi_BroadcastPacketsSent = 0;
    output_struct->wifi_BroadcastPacketsRecevied = 0;
    output_struct->wifi_UnknownPacketsReceived = 0;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
    INT status = RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //Below values should get updated from hal
    output_struct->wifi_RetransCount=0;
    output_struct->wifi_FailedRetransCount=0;
    output_struct->wifi_RetryCount=0;
    output_struct->wifi_MultipleRetryCount=0;
    output_struct->wifi_ACKFailureCount=0;
    output_struct->wifi_AggregatedPacketCount=0;

    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return status;
}

INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
    INT status = RETURN_ERR;
    UINT index;
    wifi_neighbor_ap_t *pt=NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size=2;
    //zqiu: HAL alloc the array and return to caller. Caller response to free it.
    *neighbor_ap_array=(wifi_neighbor_ap_t *)calloc(sizeof(wifi_neighbor_ap_t), *output_array_size);
    for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
        strcpy(pt->ap_Radio,"");
        strcpy(pt->ap_SSID,"");
        strcpy(pt->ap_BSSID,"");
        strcpy(pt->ap_Mode,"");
        pt->ap_Channel=1;
        pt->ap_SignalStrength=0;
        strcpy(pt->ap_SecurityModeEnabled,"");
        strcpy(pt->ap_EncryptionMode,"");
        strcpy(pt->ap_OperatingFrequencyBand,"");
        strcpy(pt->ap_SupportedStandards,"");
        strcpy(pt->ap_OperatingStandards,"");
        strcpy(pt->ap_OperatingChannelBandwidth,"");
        pt->ap_BeaconPeriod=1;
        pt->ap_Noise=0;
        strcpy(pt->ap_BasicDataTransferRates,"");
        strcpy(pt->ap_SupportedDataTransferRates,"");
        pt->ap_DTIMPeriod=1;
        pt->ap_ChannelUtilization = 1;
    }

    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return status;
}

//----------------- AP HAL -------------------------------

//>> Deprecated: used for old RDKB code.
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct)
{
    if (NULL == output_ulong || NULL == output_struct)
        return RETURN_ERR;
    *output_ulong = 0;
    *output_struct = NULL;
    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int AssoDevInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    char mac_addr[20];
    static int count=0;
    int rate=0;

    wifi_device_info_t *out = (wifi_device_info_t*)arg;

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }


    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    //devIndex starts from 1
    if( ++count == out->wifi_devIndex )
    {
        mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
        //Getting the mac addrress
        mac_addr_aton(out->wifi_devMacAddress,mac_addr);

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return NL_SKIP;
        }

        if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devTxRate = rate/10;
        }

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return NL_SKIP;
        }

        if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devRxRate = rate/10;
        }
        if(sinfo[NL80211_STA_INFO_SIGNAL_AVG])
            out->wifi_devSignalStrength = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

        out->wifi_devAssociatedDeviceAuthentiationState = 1;
        count = 0; //starts the count for next cycle
        return NL_STOP;
    }

    return NL_SKIP;

}
#endif

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[10];

    wifi_device_info_t info;
    info.wifi_devIndex = devIndex;

    snprintf(if_name,sizeof(if_name),"%s%d", AP_PREFIX, apIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_STATION,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,AssoDevInfo_callback,&info);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);

    output_struct->wifi_devAssociatedDeviceAuthentiationState = info.wifi_devAssociatedDeviceAuthentiationState;
    output_struct->wifi_devRxRate = info.wifi_devRxRate;
    output_struct->wifi_devTxRate = info.wifi_devTxRate;
    output_struct->wifi_devSignalStrength = info.wifi_devSignalStrength;
    memcpy(&output_struct->wifi_devMacAddress, &info.wifi_devMacAddress, sizeof(info.wifi_devMacAddress));
    return RETURN_OK;
#else
    //iw utility to retrieve station information
#define ASSODEVFILE "/tmp/AssociatedDevice_Stats.txt"
#define SIGNALFILE "/tmp/wifi_signalstrength.txt"
#define MACFILE "/tmp/wifi_AssoMac.txt"
#define TXRATEFILE "/tmp/wifi_txrate.txt"
#define RXRATEFILE "/tmp/wifi_rxrate.txt"
    FILE *file = NULL;
    char if_name[10] = {'\0'};
    char pipeCmd[256] = {'\0'};
    char line[256];
    int count,device = 0;

    snprintf(if_name,sizeof(if_name),"%s%d", AP_PREFIX, apIndex);

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", if_name, if_name);
    file = popen(pipeCmd, "r");

    if(file == NULL)
        return RETURN_ERR; //popen failed

    fgets(line, sizeof line, file);
    device = atoi(line);
    pclose(file);

    if(device == 0)
        return RETURN_ERR; //No devices are connected

    sprintf(pipeCmd,"iw dev %s station dump > "ASSODEVFILE, if_name);
    system(pipeCmd);

    system("cat "ASSODEVFILE" | grep 'signal avg' | cut -d ' ' -f2 | cut -d ':' -f2 | cut -f 2 | tr -s '\n' > "SIGNALFILE);

    system("cat  "ASSODEVFILE" | grep Station | cut -d ' ' -f 2  > "MACFILE);

    system("cat  "ASSODEVFILE" | grep 'tx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "TXRATEFILE);

    system("cat  "ASSODEVFILE" | grep 'rx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "RXRATEFILE);

    //devIndex starts from 1, ++count
    if((file = fopen(SIGNALFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devSignalStrength = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_signalstrength.txt failed");

    if((file = fopen(MACFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                sscanf(line, "%02x:%02x:%02x:%02x:%02x:%02x",&output_struct->wifi_devMacAddress[0],&output_struct->wifi_devMacAddress[1],&output_struct->wifi_devMacAddress[2],&output_struct->wifi_devMacAddress[3],&output_struct->wifi_devMacAddress[4],&output_struct->wifi_devMacAddress[5]);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_AssoMac.txt failed");

    if((file = fopen(TXRATEFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devTxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_txrate.txt failed");

    if((file = fopen(RXRATEFILE, "r")) != NULL)
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devRxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_rxrate.txt failed");

    output_struct->wifi_devAssociatedDeviceAuthentiationState = 1;

    return RETURN_OK;
#endif
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
    if (NULL == device)
        return RETURN_ERR;
    return RETURN_OK;
}
//<<


//--------------wifi_ap_hal-----------------------------
//enables CTS protection for the radio used by this AP
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable)
{
    //save config and Apply instantly
    return RETURN_ERR;
}

// enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable)
{
    //save config and Apply instantly
    return RETURN_ERR;
}

//P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold)
{
    char cmd[64];
    char buf[512];
    //save config and apply instantly

    //zqiu:TODO: save config
    if (threshold > 0)  {
        snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag %d", AP_PREFIX, apIndex, threshold);
    } else {
        snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag off", AP_PREFIX, apIndex );
    }
    _syscmd(cmd,buf, sizeof(buf));

    return RETURN_OK;
}

// enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable)
{
    //Save config and Apply instantly
    return RETURN_ERR;
}

// outputs A-MSDU enable status, 0 == not enabled, 1 == enabled
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool)
{
    return RETURN_ERR;
}

// enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable)
{
    //Apply instantly
    return RETURN_ERR;
}

//P2  // outputs the number of Tx streams
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int)
{
    return RETURN_ERR;
}

//P2  // sets the number of Tx streams to an enviornment variable
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams)
{
    //save to wifi config, wait for wifi reset or wifi_pushTxChainMask to apply
    return RETURN_ERR;
}

//P2  // outputs the number of Rx streams
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int)
{
    if (NULL == output_int)
        return RETURN_ERR;
    *output_int = 1;
    return RETURN_OK;
}

//P2  // sets the number of Rx streams to an enviornment variable
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams)
{
    //save to wifi config, wait for wifi reset or wifi_pushRxChainMask to apply
    return RETURN_ERR;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio ADDBA enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio auto block ack enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio 11n pure mode enable support
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Get radio 11n pure mode enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio 11n pure mode enable setting
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio IGMP snooping enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get the Reset count of radio
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int) 
{
    if (NULL == output_int) 
        return RETURN_ERR;
    *output_int = (radioIndex==0)? 1: 3;

    return RETURN_OK;
}


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------

// creates a new ap and pushes these parameters to the hardware
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid)
{
    char buf[1024];
    char cmd[128];

    if (NULL == essid)
        return RETURN_ERR;

    snprintf(cmd,sizeof(cmd), "wlanconfig %s%d create wlandev %s%d wlanmode ap", AP_PREFIX, apIndex, RADIO_PREFIX, radioIndex);
    _syscmd(cmd, buf, sizeof(buf));

    snprintf(cmd,sizeof(cmd), "iwconfig %s%d essid %s mode master", AP_PREFIX, apIndex, essid);
    _syscmd(cmd, buf, sizeof(buf));

    wifi_pushSsidAdvertisementEnable(apIndex, !hideSsid);    

    snprintf(cmd,sizeof(cmd), "ifconfig %s%d txqueuelen 1000", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

// deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_deleteAp(INT apIndex)
{
    char buf[1024];
    char cmd[128];

    snprintf(cmd,sizeof(cmd),  "wlanconfig %s%d destroy", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    wifi_removeApSecVaribles(apIndex);

    return RETURN_OK;
}

// Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller
INT wifi_getApName(INT apIndex, CHAR *output_string)
{
    if(NULL == output_string)
        return RETURN_ERR;

    snprintf(output_string, 16, "%s%d", AP_PREFIX, apIndex);
    return RETURN_OK;
}

// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *output_int)
{
    CHAR *pos = NULL;

    *output_int = -1;
    pos = strstr(inputSsidString, AP_PREFIX);
    if(pos) 
    {
        sscanf(pos+strlen(AP_PREFIX),"%d", output_int);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_getApIndexFromName(CHAR *inputSsidString, INT *output_int)
{
    return wifi_getIndexFromName(inputSsidString, output_int);
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex, "wpa", buf, sizeof(buf));
    if((strcmp(buf,"3")==0))
        snprintf(output_string, 32, "WPAand11i");
    else if((strcmp(buf,"2")==0))
        snprintf(output_string, 32, "11i");
    else if((strcmp(buf,"1")==0))
        snprintf(output_string, 32, "WPA");
    else
        snprintf(output_string, 32, "None");

    return RETURN_OK;
}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
    struct params list;

    if (NULL == beaconTypeString)
        return RETURN_ERR;
    list.name = "wpa";
    list.value = "0";

    if((strcmp(beaconTypeString,"WPAand11i")==0))
        list.value="3";
    else if((strcmp(beaconTypeString,"11i")==0))
        list.value="2";
    else if((strcmp(beaconTypeString,"WPA")==0))
        list.value="1";

    wifi_hostapdWrite(apIndex, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
    return RETURN_OK;
}

// sets the beacon interval on the hardware for this AP
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval)
{
    //save config and apply instantly
    return RETURN_ERR;
}

INT wifi_setDTIMInterval(INT apIndex, INT dtimInterval)
{
    //save config and apply instantly
    return RETURN_ERR;
}

// Get the packet size threshold supported.
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool)
{
    //save config and apply instantly
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = FALSE;
    return RETURN_OK;
}

// sets the packet size threshold in bytes to apply RTS/CTS backoff rules.
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold)
{
    char cmd[128];
    char buf[512];

    if (threshold > 0)
        snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts %d", AP_PREFIX, apIndex, threshold);
    else
        snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts off", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string)
{
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 32, "TKIPandAESEncryption");
    return RETURN_OK;

}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *param_name, buf[32];

    if(NULL == output_string)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex,"wpa",buf,sizeof(buf));

    if(strcmp(buf,"0")==0)
    {
        printf("%s: wpa_mode is %s ......... \n", __func__, buf);
        snprintf(output_string, 32, "None");
        return RETURN_OK;
    }
    else if((strcmp(buf,"3")==0) || (strcmp(buf,"2")==0))
        param_name = "rsn_pairwise";
    else if((strcmp(buf,"1")==0))
        param_name = "wpa_pairwise";
    else
        return RETURN_ERR;
    memset(output_string,'\0',32);
    wifi_hostapdRead(apIndex,param_name,output_string,32);
    wifi_dbg_printf("\n%s output_string=%s",__func__,output_string);

    if(strcmp(output_string,"TKIP") == 0)
        strncpy(output_string,"TKIPEncryption", strlen("TKIPEncryption"));
    else if(strcmp(output_string,"CCMP") == 0)
        strncpy(output_string,"AESEncryption", strlen("AESEncryption"));
    else if(strcmp(output_string,"TKIP CCMP") == 0)
        strncpy(output_string,"TKIPandAESEncryption", strlen("TKIPandAESEncryption"));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char output_string[32];

    memset(output_string,'\0',32);
    wifi_getApWpaEncryptionMode(apIndex,output_string);

    if(strcmp(encMode, "TKIPEncryption") == 0)
        params.value = "TKIP";
    else if(strcmp(encMode,"AESEncryption") == 0)
        params.value = "CCMP";
    else if(strcmp(encMode,"TKIPandAESEncryption") == 0)
        params.value = "TKIP CCMP";

    if((strcmp(output_string,"WPAand11i")==0))
    {
        params.name = "wpa_pairwise";
        wifi_hostapdWrite(apIndex, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);

        params.name,"rsn_pairwise";
        wifi_hostapdWrite(apIndex, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);

        return RETURN_OK;
    }
    else if((strcmp(output_string,"11i")==0))
    {
        params.name = "rsn_pairwise";
        wifi_hostapdWrite(apIndex, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);
        return RETURN_OK;
    }
    else if((strcmp(output_string,"WPA")==0))
    {
        params.name = "wpa_pairwise";
        wifi_hostapdWrite(apIndex, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);
        return RETURN_OK;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// deletes internal security varable settings for this ap
INT wifi_removeApSecVaribles(INT apIndex)
{
    //TODO: remove the entry in hostapd config file
    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/nvram\\/etc\\/wpa2\\/WSC_%s%d.conf//g' /tmp/conf_filename", AP_PREFIX, apIndex);
    //_syscmd(cmd, buf, sizeof(buf));

    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/tmp\\//sec%s%d//g' /tmp/conf_filename", AP_PREFIX, apIndex);
    //_syscmd(cmd, buf, sizeof(buf));
    return RETURN_ERR;
}

// changes the hardware settings to disable encryption on this ap
INT wifi_disableApEncryption(INT apIndex)
{
    //Apply instantly
    return RETURN_ERR;
}

// set the authorization mode on this ap
// mode mapping as: 1: open, 2: shared, 4:auto
INT wifi_setApAuthMode(INT apIndex, INT mode)
{
    //Apply instantly
    return RETURN_ERR;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    struct params params={'\0'};
    int ret;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(authMode ==  NULL)
        return RETURN_ERR;

    wifi_dbg_printf("\n%s AuthMode=%s",__func__,authMode);
    params.name = "wpa_key_mgmt";

    if((strcmp(authMode,"PSKAuthentication") == 0) || (strcmp(authMode,"SharedAuthentication") == 0))
        params.value = "WPA-PSK";
    else if(strcmp(authMode,"EAPAuthentication") == 0)
        params.value = "WPA-EAP";
    else if(strcmp(authMode,"None") == 0) //Donot change in case the authMode is None
        return RETURN_OK;			  //This is taken careof in beaconType

    ret=wifi_hostapdWrite(apIndex, &params, 1);
    if(!ret)
        ret=wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return ret;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_getApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    char BeaconType[50] = {0};

    *authMode = 0;
    wifi_getApBeaconType(apIndex,BeaconType);
    printf("%s____%s \n",__FUNCTION__,BeaconType);

    if(strcmp(BeaconType,"None") == 0)
        strcpy(authMode,"None");
    else
    {
        wifi_hostapdRead(apIndex, "wpa_key_mgmt", authMode, 32);
        wifi_dbg_printf("\n[%s]: AuthMode Name is : %s",__func__,authMode);
        if(strcmp(authMode,"WPA-PSK") == 0)
            strcpy(authMode,"SharedAuthentication");
        else if(strcmp(authMode,"WPA-EAP") == 0)
            strcpy(authMode,"EAPAuthentication");
    }

    return RETURN_OK;
}

// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
    char cmd[128]={0};
    char buf[128]={0};
    BOOL status = false;

    if(apIndex > MAX_APS)
        return RETURN_ERR;

    wifi_getApEnable(apIndex,&status);
    if (!status)
        return RETURN_OK;

    //sprintf(cmd, "iw dev %s%d station dump | grep Station | wc -l", AP_PREFIX, apIndex);//alternate method
    sprintf(cmd, "hostapd_cli -i %s%d list_sta | wc -l", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    sscanf(buf,"%lu", output_ulong);

    return RETURN_OK;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac)
{
    char buf[126]={'\0'};

    sprintf(buf,"hostapd_cli -i%s%d disassociate %s", AP_PREFIX, apIndex, client_mac);
    system(buf);

    return RETURN_OK;
}

// outputs the radio index for the specified ap. similar as wifi_getSsidRadioIndex
INT wifi_getApRadioIndex(INT apIndex, INT *output_int)
{
    if(NULL == output_int)
        return RETURN_ERR;
    *output_int = apIndex%2;
    return RETURN_OK;
}

// sets the radio index for the specific ap
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex)
{
    //set to config only and wait for wifi reset to apply settings
    return RETURN_ERR;
}

// Get the ACL MAC list per AP
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    int ret = 0;
    BOOL apEnabled = false;

    wifi_getApEnable(apIndex, &apEnabled);
    if (apEnabled)
    {
        snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d accept_acl SHOW | awk '{print $1}'", AP_PREFIX, apIndex);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "cat %s%d", ACL_PREFIX, apIndex);
    }

    ret = _syscmd(cmd,macArray,buf_size);

    if (ret != 0)
        return RETURN_ERR;

    return RETURN_OK;
}

// Get the list of stations associated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size)
{
    char cmd[128];

    if(apIndex > 3) //Currently supporting apIndex upto 3
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s%d list_sta", AP_PREFIX, apIndex);
    //sprintf(buf,"iw dev %s%d station dump | grep Station  | cut -d ' ' -f2", AP_PREFIX,apIndex);//alternate method
    _syscmd(cmd, macArray, buf_size);

    return RETURN_OK;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    BOOL apEnabled = false;

    sprintf(cmd, "echo '%s' >> %s%d", DeviceMacAddress, ACL_PREFIX, apIndex);
    if(_syscmd(cmd,buf,sizeof(buf)))
        return RETURN_ERR;

    wifi_getApEnable(apIndex, &apEnabled);
    if (apEnabled)
    {
        sprintf(cmd, "hostapd_cli -i %s%d accept_acl ADD_MAC %s", AP_PREFIX,apIndex,DeviceMacAddress);
        if(_syscmd(cmd,buf,sizeof(buf)))
            return RETURN_ERR;
    }

    return RETURN_OK;
}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    BOOL apEnabled = false;

    sprintf(cmd, "sed -i '/%s/d' %s%d ", DeviceMacAddress, ACL_PREFIX, apIndex);
    if(_syscmd(cmd,buf,sizeof(buf)))
        return RETURN_ERR;

    wifi_getApEnable(apIndex, &apEnabled);
    if (apEnabled)
    {
        sprintf(cmd, "hostapd_cli -i %s%d accept_acl DEL_MAC %s", AP_PREFIX,apIndex,DeviceMacAddress);
        if(_syscmd(cmd,buf,sizeof(buf)))
            return RETURN_ERR;
    }

    return RETURN_OK;
}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)
{
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char buf[4] = {'\0'};
    int ret = 0;
    BOOL apEnabled = false;

    if (NULL == output_uint)
        return RETURN_ERR;

    wifi_getApEnable(apIndex, &apEnabled);
    if (apEnabled)
    {
        snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d accept_acl SHOW | wc -l", AP_PREFIX, apIndex);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "cat %s%d | wc -l", ACL_PREFIX, apIndex);
    }

    ret = _syscmd(cmd, buf, sizeof(buf));

    if (ret != 0)
        return RETURN_ERR;

    *output_uint = atoi(buf);
    return RETURN_OK;
}

INT apply_rules(INT apIndex, CHAR *client_mac,CHAR *action,CHAR *interface)
{
        char cmd[128]={'\0'};
        char buf[128]={'\0'};

        if(strcmp(action,"DENY")==0)
        {
            sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",apIndex,interface,client_mac);
            system(buf);
            return RETURN_OK;
        }

        if(strcmp(action,"ALLOW")==0)
        {
            sprintf(buf,"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",apIndex,interface,client_mac);
            system(buf);
            return RETURN_OK;
        }

        return RETURN_ERR;

}

// enable kick for devices on acl black list
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)
{
    char aclArray[512] = {0}, *acl = NULL;
    char assocArray[512] = {0}, *asso = NULL;

    wifi_getApAclDevices(apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated(apIndex, assocArray, sizeof(assocArray));

    // if there are no devices connected there is nothing to do
    if (strlen(assocArray) < 17)
        return RETURN_OK;

    if (enable == TRUE)
    {
        //kick off the MAC which is in ACL array (deny list)
        acl = strtok(aclArray, "\r\n");
        while (acl != NULL) {
            if (strlen(acl) >= 17 && strcasestr(assocArray, acl))
                wifi_kickApAssociatedDevice(apIndex, acl);

            acl = strtok(NULL, "\r\n");
        }
    }
    else
    {
        //kick off the MAC which is not in ACL array (allow list)
        asso = strtok(assocArray, "\r\n");
        while (asso != NULL) {
            if (strlen(asso) >= 17 && !strcasestr(aclArray, asso))
                wifi_kickApAssociatedDevice(apIndex, asso);

            asso = strtok(NULL, "\r\n");
        }
    }

#if 0
    //TODO: need to revisit below implementation
    char aclArray[512]={0}, *acl=NULL;
    char assocArray[512]={0}, *asso=NULL;
    char buf[256]={'\0'};
    char action[10]={'\0'};
    FILE *fr=NULL;
    char interface[10]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    wifi_getApAclDevices( apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated( apIndex, assocArray, sizeof(assocArray));
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"interface",interface,sizeof(interface));

    sprintf(buf,"iptables -F  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -D INPUT  -j WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -X  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -N  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -I INPUT 21 -j WifiServices%d",apIndex);
    system(buf);

    if ( enable == TRUE )
    {
        int device_count=0;
        strcpy(action,"DENY");
        //kick off the MAC which is in ACL array (deny list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
            if(strlen(acl)>=17)
            {
                apply_rules(apIndex, acl,action,interface);
                device_count++;
                //Register mac to be blocked ,in syscfg.db persistent storage 
                sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                system(buf);
                sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                system(buf);
                system("syscfg commit");

                wifi_kickApAssociatedDevice(apIndex, acl);
            }
            acl = strtok (NULL, ",");
        }
    }
    else
    {
        int device_count=0;
        char cmdmac[20]={'\0'};
        strcpy(action,"ALLOW");
        //kick off the MAC which is not in ACL array (allow list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
            if(strlen(acl)>=17)
            {
                apply_rules(apIndex, acl,action,interface);
                device_count++;
                //Register mac to be Allowed ,in syscfg.db persistent storage 
                sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                system(buf);
                sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                system(buf);
                sprintf(cmdmac,"%s",acl);
            }
            acl = strtok (NULL, ",");
        }
        sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",apIndex,interface,cmdmac);
        system(buf);

        //Disconnect the mac which is not in ACL
        asso = strtok (assocArray,",");
        while (asso != NULL) {
            if(strlen(asso)>=17 && !strcasestr(aclArray, asso))
                wifi_kickApAssociatedDevice(apIndex, asso);
            asso = strtok (NULL, ",");
        }
    }
#endif
    return RETURN_OK;
}

INT wifi_setPreferPrivateConnection(BOOL enable)
{
    char interface_name[100] = {0};
    char ssid_cur_value[50] = {0};
    char buf[1024] = {0};

    fprintf(stderr,"%s Value of %d",__FUNCTION__,enable);
    if(enable == TRUE)
    {
        GetInterfaceName(AP_IDX_2G_PUBLIC, interface_name);
        sprintf(buf,"ifconfig %s down" ,interface_name);
        system(buf);
        memset(buf,0,sizeof(buf));
        GetInterfaceName(AP_IDX_5G_PUBLIC, interface_name);
        sprintf(buf,"ifconfig %s down" ,interface_name);
        system(buf);
    }
    else
    {
        File_Reading("cat /tmp/Get5gssidEnable.txt", ssid_cur_value);
        if(strcmp(ssid_cur_value,"1") == 0)
            wifi_RestartPrivateWifi_5G();
        memset(ssid_cur_value,0,sizeof(ssid_cur_value));
        File_Reading("cat /tmp/GetPub2gssidEnable.txt", ssid_cur_value);
        if(strcmp(ssid_cur_value,"1") == 0)
            wifi_RestartHostapd_2G();
        memset(ssid_cur_value,0,sizeof(ssid_cur_value));
        File_Reading("cat /tmp/GetPub5gssidEnable.txt", ssid_cur_value);
        if(strcmp(ssid_cur_value,"1") == 0)
            wifi_RestartHostapd_5G();
    }
    return RETURN_OK;
}

// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    int items = 1;
    struct params list[2];
    char buf[MAX_BUF_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0}, acl_file[MAX_BUF_SIZE] = {0};

    list[0].name = "macaddr_acl";
    sprintf(buf, "%d", filterMode);
    list[0].value = buf ;

    if (filterMode == 0 || filterMode == 1) {//TODO: check for filterMode(2)
        sprintf(acl_file,"%s%d",ACL_PREFIX,apIndex);
        list[1].name = "accept_mac_file";
        list[1].value = acl_file;
        items = 2;
    }
    wifi_hostapdWrite(apIndex, list, items);

    return RETURN_OK;

#if 0
    if(apIndex==0 || apIndex==1)
    {
        //set the filtermode
        sprintf(buf,"syscfg set %dblockall %d",apIndex,filterMode);
        system(buf);
        system("syscfg commit");

        if(filterMode==0)
        {
            sprintf(buf,"iptables -F  WifiServices%d",apIndex);
            system(buf);
            return RETURN_OK;
        }
    }
    return RETURN_OK;
#endif
}

// enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled)
{
    return RETURN_ERR;
}

// gets the vlan ID for this ap from an internal enviornment variable
INT wifi_getApVlanID(INT apIndex, INT *output_int)
{
    if(apIndex=0)
    {
        *output_int=100;
        return RETURN_OK;
    }

    return RETURN_ERR;
}

// sets the vlan ID for this ap to an internal enviornment variable
INT wifi_setApVlanID(INT apIndex, INT vlanId)
{
    //save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
    return RETURN_ERR;
}

// gets bridgeName, IP address and Subnet. bridgeName is a maximum of 32 characters,
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
    snprintf(bridgeName, 32, "brlan0");
    snprintf(IP, 32, "10.0.0.1");
    snprintf(subnet, 32, "255.255.255.0");

    return RETURN_OK;
}

//sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
    //save settings, wait for wifi reset or wifi_pushBridgeInfo to apply.
    return RETURN_ERR;
}

// reset the vlan configuration for this ap
INT wifi_resetApVlanCfg(INT apIndex)
{
    //TODO: remove existing vlan for this ap

    //Reapply vlan settings
    wifi_pushBridgeInfo(apIndex);

    return RETURN_ERR;
}

// creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg)
{
    return RETURN_ERR;
}

// starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_startHostApd()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    system("systemctl start hostapd.service");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
    //sprintf(cmd, "hostapd  -B `cat /tmp/conf_filename` -e /nvram/etc/wpa2/entropy -P /tmp/hostapd.pid 1>&2");
}

// stops hostapd
INT wifi_stopHostApd()                                        
{
    char cmd[128] = {0};
    char buf[128] = {0};

    sprintf(cmd,"systemctl stop hostapd");
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

// restart hostapd dummy function
INT wifi_restartHostApd()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    system("systemctl restart hostapd-global");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

static int align_hostapd_config(int index)
{
    ULONG lval;
    wifi_getRadioChannel(index%2, &lval);
    wifi_setRadioChannel(index%2, lval);
}

// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
    char config_file[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    BOOL status;

    wifi_getApEnable(apIndex,&status);
    if (enable == status)
        return RETURN_OK;

    if (enable == TRUE) {
	int radioIndex = apIndex % NUMBER_OF_RADIOS;
        align_hostapd_config(apIndex);
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        //Hostapd will bring up this interface
        sprintf(cmd, "hostapd_cli -i global raw REMOVE %s%d", AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
        sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=phy%d:%s", radioIndex, config_file);
        _syscmd(cmd, buf, sizeof(buf));
    }
    else {
        sprintf(cmd, "hostapd_cli -i global raw REMOVE %s%d", AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
        sprintf(cmd, "ip link set %s%d down", AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
    }
    snprintf(cmd, sizeof(cmd), "sed '/%s%d/c %s%d=%d' -i %s",
                  AP_PREFIX, apIndex, AP_PREFIX, apIndex, enable, VAP_STATUS_FILE);
    _syscmd(cmd, buf, sizeof(buf));
    //Wait for wifi up/down to apply
    return RETURN_OK;
}

// Outputs the setting of the internal variable that is set by wifi_setApEnable().
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};

    if((!output_bool) || (apIndex < 0) || (apIndex >= MAX_APS))
        return RETURN_ERR;

    *output_bool = 0;

    if((apIndex >= 0) && (apIndex < MAX_APS))//Handling 6 APs
    {
        sprintf(cmd, "%s%s%d%s", "hostapd_cli -i", AP_PREFIX, apIndex, " ping &> /dev/null");
        *output_bool = _syscmd(cmd,buf,sizeof(buf))?0:1;
    }

    return RETURN_OK;
}

// Outputs the AP "Enabled" "Disabled" status from driver 
INT wifi_getApStatus(INT apIndex, CHAR *output_string) 
{
    char cmd[128] = {0};
    char buf[128] = {0};
    BOOL output_bool;

    if ( NULL == output_string)
        return RETURN_ERR;
    wifi_getApEnable(apIndex,&output_bool);

    if(output_bool == 1) 
        snprintf(output_string, 32, "Up");
    else
        snprintf(output_string, 32, "Disable");

    return RETURN_OK;
}

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else outputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output)
{
    //get the running status
    char buf[16] = {0};

    if (!output)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex, "ignore_broadcast_ssid", buf, sizeof(buf));
    *output = (strncmp("0",buf,1) == 0);

    return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
    //store the config, apply instantly
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    list.name = "ignore_broadcast_ssid";
    list.value = enable?"0":"1";

    wifi_hostapdWrite(apIndex, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    //TODO: call hostapd_cli for dynamic_config_control
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
    char cmd[MAX_BUF_SIZE]={'\0'};
    char buf[MAX_CMD_SIZE]={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(output_uint == NULL)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd),  "iw phy phy%d info | grep 'Retry short limit' | awk '{print $4}' | tr -d '\n'", apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    *output_uint = atoi(buf);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
    char cmd[MAX_BUF_SIZE]={'\0'};
    char buf[MAX_CMD_SIZE]={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    if (number < 1 || number > 31) {
        WIFI_ENTRY_EXIT_DEBUG("%s Invalid input: %d\n", __func__, number);
        return RETURN_ERR;
    }

    snprintf(cmd, sizeof(cmd),  "iw phy phy%d set retry short %d", apIndex, number);
    _syscmd(cmd, buf, sizeof(buf));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
    if(!output)
        return RETURN_ERR;
    *output=TRUE;
    return RETURN_OK;
}

//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output)
{
    //get the running status from driver
    if(!output)
        return RETURN_ERR;
    *output=TRUE;
    return RETURN_OK;
}

//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output)
{
    //get the running status from driver
    if(!output)
        return RETURN_ERR;
    *output=TRUE;
    return RETURN_OK;
}

// enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0
INT wifi_setApWmmEnable(INT apIndex, BOOL enable)
{
    //Save config and apply instantly.
    return RETURN_ERR;
}

//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output)
{
    //get the running status from driver
    if(!output)
        return RETURN_ERR;
    *output=TRUE;
    return RETURN_OK;
}

// enables/disables Automatic Power Save Delivery on the hardwarwe for this AP
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable)
{
    //save config and apply instantly.
    return RETURN_ERR;
}

// Sets the WMM ACK polity on the hardware. AckPolicy false means do not acknowledge, true means acknowledge
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy)  //RDKB
{
    //save config and apply instantly.
    return RETURN_ERR;
}

//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output_uint)
{
    //get the running status from driver
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 5;
    return RETURN_OK;
}

INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number)
{
    //store to wifi config, apply instantly
    return RETURN_ERR;
}

//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output_uint)
{
    //get the current threshold
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 50;
    return RETURN_OK;
}

INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold)
{
    //store the config, reset threshold, reset AssociatedDevicesHighWatermarkThresholdReached, reset AssociatedDevicesHighWatermarkDate to current time
    return RETURN_ERR;
}

//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output_uint)
{
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 3;
    return RETURN_OK;
}

//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output_uint)
{
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 3;
    return RETURN_OK;
}

//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds)
{
    if(!output_in_seconds)
        return RETURN_ERR;
    *output_in_seconds = 0;
    return RETURN_OK;
}

//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output)
{
    if(!output || apIndex>=MAX_APS)
        return RETURN_ERR;
    //snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
    snprintf(output, 128, "None,WPA2-Personal");
    return RETURN_OK;
}		

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
    char buf[32] = {0};
    if (!output)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex, "wpa", buf, sizeof(buf));

    strcpy(output,"None");//Copying "None" to output string for default case
    if((strcmp(buf, "3")==0))
        snprintf(output, 32, "WPA-WPA2-Personal");
    else if((strcmp(buf, "2")==0))
        snprintf(output, 32, "WPA2-Personal");
    else if((strcmp(buf, "1")==0))
        snprintf(output, 32, "WPA-Personal");
    //TODO: need to handle enterprise authmode

    //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
    return RETURN_OK;
#if 0
    //TODO: need to revisit below implementation
    char securityType[32], authMode[32];
    int enterpriseMode=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(!output)
        return RETURN_ERR;

    wifi_getApBeaconType(apIndex, securityType);
    strcpy(output,"None");//By default, copying "None" to output string
    if (strncmp(securityType,"None", strlen("None")) == 0)
        return RETURN_OK;

    wifi_getApBasicAuthenticationMode(apIndex, authMode);
    enterpriseMode = (strncmp(authMode, "EAPAuthentication", strlen("EAPAuthentication")) == 0)? 1: 0;

    if (strncmp(securityType, "WPAand11i", strlen("WPAand11i")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA-WPA2-Enterprise": "WPA-WPA2-Personal");
    else if (strncmp(securityType, "WPA", strlen("WPA")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA-Enterprise": "WPA-Personal");
    else if (strncmp(securityType, "11i", strlen("11i")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA2-Enterprise": "WPA2-Personal");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#endif
}
  
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
    char securityType[32];
    char authMode[32];

    //store settings and wait for wifi up to apply
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(!encMode)
        return RETURN_ERR;

    printf("%s: apIndex %d, encMode %s\n",__func__, apIndex, encMode);
    if (strcmp(encMode, "None")==0)
    {
        strcpy(securityType,"None");
        strcpy(authMode,"None");
    }
    else if (strcmp(encMode, "WPA-WPA2-Personal")==0)
    {
        strcpy(securityType,"WPAand11i");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA-WPA2-Enterprise")==0)
    {
        strcpy(securityType,"WPAand11i");
        strcpy(authMode,"EAPAuthentication");
    }
    else if (strcmp(encMode, "WPA-Personal")==0)
    {
        strcpy(securityType,"WPA");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA-Enterprise")==0)
    {
        strcpy(securityType,"WPA");
        strcpy(authMode,"EAPAuthentication");
    }
    else if (strcmp(encMode, "WPA2-Personal")==0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA2-Enterprise")==0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"EAPAuthentication");
    }
    else
    {
        strcpy(securityType,"None");
        strcpy(authMode,"None");
    }
    wifi_setApBeaconType(apIndex, securityType);
    wifi_setApBasicAuthenticationMode(apIndex, authMode);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}   


//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
// output_string must be pre-allocated as 64 character string by caller
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{
    char buf[16];

    if(output_string==NULL)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex,"wpa",buf,sizeof(buf));

    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        return RETURN_ERR;
    }

    wifi_dbg_printf("\nFunc=%s\n",__func__);
    wifi_hostapdRead(apIndex,"wpa_passphrase",output_string,64);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)
{
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    int ret;

    if(NULL == preSharedKey)
        return RETURN_ERR;

    params.name = "wpa_passphrase";

    if(strlen(preSharedKey)<8 || strlen(preSharedKey)>63)
    {
        wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
        return RETURN_ERR;
    }
    params.value = preSharedKey;
    ret = wifi_hostapdWrite(apIndex, &params, 1);
    if(!ret)
        ret = wifi_hostapdProcessUpdate(apIndex, &params, 1);
    return ret;
    //TODO: call hostapd_cli for dynamic_config_control
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string)
{
    char buf[32] = {0};

    wifi_dbg_printf("\nFunc=%s\n",__func__);
    if (NULL == output_string)
        return RETURN_ERR;

    wifi_hostapdRead(apIndex,"wpa",buf,sizeof(buf));
    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        return RETURN_ERR;
    }

    wifi_hostapdRead(apIndex,"wpa_passphrase",output_string,64);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    int ret;

    if(NULL == passPhrase)
        return RETURN_ERR;

    if(strlen(passPhrase)<8 || strlen(passPhrase)>63)
    {
        wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
        return RETURN_ERR;
    }
    params.name = "wpa_passphrase";
    params.value = passPhrase;
    ret=wifi_hostapdWrite(apIndex, &params, 1);
    if(!ret)
        wifi_hostapdProcessUpdate(apIndex, &params, 1);

    return ret;
}

//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex)
{
    //apply instantly
    return RETURN_ERR;
}

//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
    if(!IP_output || !Port_output || !RadiusSecret_output)
        return RETURN_ERR;
    snprintf(IP_output, 64, "75.56.77.78");
    *Port_output = 123;
    snprintf(RadiusSecret_output, 64, "12345678");

    return RETURN_OK;
}

INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
    //store the paramters, and apply instantly
    return RETURN_ERR;
}

INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
    if(!IP_output || !Port_output || !RadiusSecret_output)
        return RETURN_ERR;
    snprintf(IP_output, 64, "75.56.77.78");
    *Port_output = 123;
    snprintf(RadiusSecret_output, 64, "12345678");
    return RETURN_OK;
}

INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
    //store the paramters, and apply instantly
    return RETURN_ERR;
}

//RadiusSettings
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output)
{
    if(!output)
        return RETURN_ERR;

    output->RadiusServerRetries = 3; 				//Number of retries for Radius requests.
    output->RadiusServerRequestTimeout = 5; 		//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.	
    output->PMKLifetime = 28800; 					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).	
    output->PMKCaching = FALSE; 					//Enable or disable caching of PMK.	
    output->PMKCacheInterval = 300; 				//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).	
    output->MaxAuthenticationAttempts = 3; 		//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
    output->BlacklistTableTimeout = 600; 			//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.	
    output->IdentityRequestRetryInterval = 5; 	//Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.	
    output->QuietPeriodAfterFailedAuthentication = 5;  	//The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.	
    //snprintf(output->RadiusSecret, 64, "12345678");		//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

    return RETURN_OK;
}

INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input)
{
    //store the paramters, and apply instantly
    return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.WPS.Enable
//Enables or disables WPS functionality for this access point.
// outputs the WPS enable state of this ap in output_bool
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool)
{
    char buf[MAX_BUF_SIZE] = {0}, cmd[MAX_CMD_SIZE] = {0}, *value;
    if(!output_bool || !(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    sprintf(cmd,"hostapd_cli -i %s%d get_config | grep wps_state | cut -d '=' -f2", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    if(strstr(buf, "configured"))
        *output_bool=TRUE;
    else
        *output_bool=FALSE;

    return RETURN_OK;
}        

//Device.WiFi.AccessPoint.{i}.WPS.Enable
// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled
INT wifi_setApWpsEnable(INT apIndex, BOOL enable)
{
    struct params params;

    if(!(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //store the paramters, and wait for wifi up to apply
    params.name = "wps_state";
    params.value = enable ? "2":"0";

    wifi_hostapdWrite(apIndex, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    wifi_reloadAp(apIndex);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
    if(!output)
        return RETURN_ERR;
    snprintf(output, 128, "PushButton,PIN");
    return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
    if(!output)
        return RETURN_ERR;
    snprintf(output, 64, "PushButton,PIN");//Currently, supporting these two methods

    return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
    //apply instantly. No setting need to be stored.
    char methods[MAX_BUF_SIZE], *token, *next_token;
    char config_methods[MAX_BUF_SIZE] = {0};
    struct params params;

    if(!methodString || !(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //store the paramters, and wait for wifi up to apply

    snprintf(methods, sizeof(methods), "%s", methodString);
    for(token=methods; *token; token=next_token)
    {
        strtok_r(token, ",", &next_token);
        if(*token=='U' && !strcmp(methods, "USBFlashDrive"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "usba");
        else if(*token=='E')
        {
            if(!strcmp(methods, "Ethernet"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "ethernet");
            else if(!strcmp(methods, "ExternalNFCToken"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "ext_nfc_token");
            else
                printf("%s: Unknown WpsConfigMethod\n", __func__);
        }
        else if(*token=='I' && !strcmp(token, "IntegratedNFCToken"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "int_nfc_token");
        else if(*token=='N' && !strcmp(token, "NFCInterface"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "nfc_interface");
        else if(*token=='P' )
        {
            if(!strcmp(token, "PushButton"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "virtual_push_button");
            else if(!strcmp(token, "PIN"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "keypad");
            else
                printf("%s: Unknown WpsConfigMethod\n", __func__);
        }
        else
            printf("%s: Unknown WpsConfigMethod\n", __func__);
    }
    params.name = "config_methods";
    params.value = config_methods;
    wifi_hostapdWrite(apIndex, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
    char buf[MAX_BUF_SIZE];

    if(!output_ulong || !(apIndex==0 || apIndex==1))
        return RETURN_ERR;

    *output_ulong = 0;
    if (RETURN_OK == wifi_hostapdRead(apIndex, "ap_pin", buf, sizeof(buf)))
    {
        *output_ulong = strtoul(buf, NULL, 10);
    }
    return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
    //set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply
    char ap_pin[16] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    ULONG prev_pin = 0;
    struct params params;

    if(!(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    snprintf(ap_pin, sizeof(ap_pin), "%lu", pin);
    params.name = "ap_pin";
    params.value = ap_pin;
    wifi_hostapdWrite(apIndex, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};

    if(!output_string || !(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    snprintf(output_string, 32, "Not configured");
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d get_config | grep wps_state | cut -d'=' -f2", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    if(!strcmp(buf, "configured"))
        snprintf(output_string, 32, "Configured");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// sets the WPS pin for this AP
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin)
{
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};
    BOOL enable;

    if(!(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    wifi_getApEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;
    wifi_getApWpsEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    snprintf(cmd, 64, "hostapd_cli -i%s%d wps_pin any %s", AP_PREFIX, apIndex, pin);
    _syscmd(cmd, buf, sizeof(buf));
    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;

    return RETURN_ERR;
}

// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};
    BOOL enable=FALSE;

    if(!(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    wifi_getApEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    wifi_getApWpsEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s%d wps_cancel; hostapd_cli -i%s%d wps_pbc", AP_PREFIX, apIndex, AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;
    return RETURN_ERR;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};

    if(!(apIndex==0 || apIndex==1))
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s%d wps_cancel", AP_PREFIX, apIndex);
    _syscmd(cmd,buf, sizeof(buf));

    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;
    return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
    FILE *f;
    int read_flag=0, auth_temp=0, mac_temp=0,i=0;
    char cmd[256], buf[2048];
    char *param , *value, *line=NULL;
    size_t len = 0;
    ssize_t nread;
    wifi_associated_dev_t *dev=NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *associated_dev_array = NULL;
    sprintf(cmd, "hostapd_cli -i%s%d all_sta | grep AUTHORIZED | wc -l", AP_PREFIX, apIndex);
    _syscmd(cmd,buf,sizeof(buf));
    *output_array_size = atoi(buf);

    if (*output_array_size <= 0)
        return RETURN_OK;

    dev=(wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
    *associated_dev_array = dev;
    sprintf(cmd, "hostapd_cli -i%s%d all_sta > /tmp/connected_devices.txt" , AP_PREFIX, apIndex);
    _syscmd(cmd,buf,sizeof(buf));
    f = fopen("/tmp/connected_devices.txt", "r");
    if (f==NULL)
    {
        *output_array_size=0;
        return RETURN_ERR;
    }
    while ((nread = getline(&line, &len, f)) != -1)
    {
        param = strtok(line,"=");
        value = strtok(NULL,"=");

        if( strcmp("flags",param) == 0 )
        {
            value[strlen(value)-1]='\0';
            if(strstr (value,"AUTHORIZED") != NULL )
            {
                dev[auth_temp].cli_AuthenticationState = 1;
                dev[auth_temp].cli_Active = 1;
                auth_temp++;
                read_flag=1;
            }
        }
        if(read_flag==1)
        {
            if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
            {
                value[strlen(value)-1]='\0';
                sscanf(value, "%x:%x:%x:%x:%x:%x",
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[0],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[1],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[2],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[3],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[4],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[5] );
                mac_temp++;
                read_flag=0;
            }
        }
    }
    *output_array_size = auth_temp;
    auth_temp=0;
    mac_temp=0;
    free(line);
    fclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

#define MACADDRESS_SIZE 6

INT wifihal_AssociatedDevicesstats3(INT apIndex,CHAR *interface_name,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    FILE *fp = NULL;
    char str[MAX_BUF_SIZE] = {0};
    int wificlientindex = 0 ;
    int count = 0;
    int signalstrength = 0;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    UINT wifi_count = 0;
    char virtual_interface_name[MAX_BUF_SIZE] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size = 0;
    *associated_dev_array = NULL;

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
    fp = popen(pipeCmd, "r");
    if (fp == NULL) 
    {
        printf("Failed to run command inside function %s\n",__FUNCTION__ );
        return RETURN_ERR;
    }

    /* Read the output a line at a time - output it. */
    fgets(str, sizeof(str)-1, fp);
    wifi_count = (unsigned int) atoi ( str );
    *output_array_size = wifi_count;
    printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
    pclose(fp);

    if(wifi_count == 0)
    {
        return RETURN_OK;
    }
    else
    {
        wifi_associated_dev3_t* temp = NULL;
        temp = (wifi_associated_dev3_t*)calloc(1, sizeof(wifi_associated_dev3_t)*wifi_count) ;
        if(temp == NULL)
        {
            printf("Error Statement. Insufficient memory \n");
            return RETURN_ERR;
        }

        snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
        system(pipeCmd);
        memset(pipeCmd,0,sizeof(pipeCmd));
        if(apIndex == 0)
            snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_2G.txt", interface_name);
        else if(apIndex == 1)
            snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_5G.txt", interface_name);
        system(pipeCmd);

        fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2", interface_name);
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            for(count =0 ; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
            }
            pclose(fp);
        }

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt", interface_name);
        fp = popen(pipeCmd, "r");
        if(fp)
        { 
            pclose(fp);
        }
        fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
        if(fp)
        {
            for(count =0 ; count < wifi_count ;count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                signalstrength = atoi(str);
                temp[count].cli_SignalStrength = signalstrength;
                temp[count].cli_RSSI = signalstrength;
                temp[count].cli_SNR = signalstrength + 95;
            }
            pclose(fp);
        }


        if((apIndex == 0) || (apIndex == 4))
        {
            for(count =0 ; count < wifi_count ;count++)
            {	
                strcpy(temp[count].cli_OperatingStandard,"g");
                strcpy(temp[count].cli_OperatingChannelBandwidth,"20MHz");
            }

            //BytesSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if(fp)
            { 
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bytes_Send.txt | tr -s ' ' | cut -f 2","r");
            if(fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_BytesSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //BytesReceived
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bytes_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_BytesReceived = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //PacketsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Send.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }

            fp = popen("cat /tmp/Ass_Packets_Send.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_PacketsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //PacketsReceived
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Received.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Packets_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_PacketsReceived = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //ErrorsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //ErrorsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //LastDataDownlinkRate
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
                    temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
                }
                pclose(fp);
            }

            //LastDataUplinkRate
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt", interface_name);
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
                    temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
                }
                pclose(fp);
            }

        }
        else if ((apIndex == 1) || (apIndex == 5))
        {
            for (count = 0; count < wifi_count; count++)
            {
                strcpy(temp[count].cli_OperatingStandard, "a");
                strcpy(temp[count].cli_OperatingChannelBandwidth, "20MHz");
                temp[count].cli_BytesSent = 0;
                temp[count].cli_BytesReceived = 0;
                temp[count].cli_LastDataUplinkRate = 0;
                temp[count].cli_LastDataDownlinkRate = 0;
                temp[count].cli_PacketsSent = 0;
                temp[count].cli_PacketsReceived = 0;
                temp[count].cli_ErrorsSent = 0;
            }
        }

        for (count = 0; count < wifi_count; count++)
        {
            temp[count].cli_Retransmissions = 0;
            temp[count].cli_DataFramesSentAck = 0;
            temp[count].cli_DataFramesSentNoAck = 0;
            temp[count].cli_MinRSSI = 0;
            temp[count].cli_MaxRSSI = 0;
            strncpy(temp[count].cli_InterferenceSources, "", 64);
            memset(temp[count].cli_IPAddress, 0, 64);
            temp[count].cli_RetransCount = 0;
            temp[count].cli_FailedRetransCount = 0;
            temp[count].cli_RetryCount = 0;
            temp[count].cli_MultipleRetryCount = 0;
        }
        *associated_dev_array = temp;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

int wifihal_interfacestatus(CHAR *wifi_status,CHAR *interface_name)
{
    FILE *fp = NULL;
    char path[512] = {0},status[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE];
    int count = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(cmd, "ifconfig %s | grep RUNNING | tr -s ' ' | cut -d ' ' -f4", interface_name);
    fp = popen(cmd,"r");
    if(fp == NULL)
    {
        printf("Failed to run command in Function %s\n",__FUNCTION__);
        return 0;
    }
    if(fgets(path, sizeof(path)-1, fp) != NULL)
    {
        for(count=0;path[count]!='\n';count++)
            status[count]=path[count];
        status[count]='\0';
    }
    strcpy(wifi_status,status);
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* #define HOSTAPD_STA_PARAM_ENTRIES 29
struct hostapd_sta_param {
    char key[50];
    char value[100];
}

static char * hostapd_st_get_param(struct hostapd_sta_param * params, char *key){
    int i = 0;

    while(i<HOSTAPD_STA_PARAM_ENTRIES) {
        if (strncmp(params[i].key,key,50) == 0){
            return &params[i].value;
        }
        i++;
    }
    return NULL;

} */

static unsigned int count_occurences(const char *buf, const char *word)
{
    unsigned int n = 0;
    char *ptr = strstr(buf, word);

    while (ptr++) {
        n++;
        ptr = strstr(ptr, word);
    }

    wifi_dbg_printf("%s: found %u of '%s'\n",  __FUNCTION__, n, word);
    return n;
}

static const char *get_line_from_str_buf(const char *buf, char *line)
{
    int i;
    int n = strlen(buf);

    for (i = 0; i < n; i++) {
        line[i] = buf[i];
        if (buf[i] == '\n') {
            line[i] = '\0';
            return &buf[i + 1];
        }
    }

    return NULL;
}

INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    unsigned int assoc_cnt = 0;
    char interface_name[50] = {0};
    char buf[MAX_BUF_SIZE * 50]= {'\0'}; // Increase this buffer if more fields are added to 'iw dev' output filter
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char line[256] = {'\0'};
    int i = 0;
    int ret = 0;
    const char *ptr = NULL;
    char *key = NULL;
    char *val = NULL;
    wifi_associated_dev3_t *temp = NULL;
    int rssi;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    // Example filtered output of 'iw dev' command:
    //    Station 0a:69:72:10:d2:fa (on wifi0)
    //    signal avg:-67 [-71, -71] dBm
    //    Station 28:c2:1f:25:5f:99 (on wifi0)
    //    signal avg:-67 [-71, -70] dBm
    if (sprintf(cmd,"iw dev %s station dump | tr -d '\\t' | grep 'Station\\|signal avg'", interface_name) < 0) {
        wifi_dbg_printf("%s: failed to build iw dev command for %s\n", __FUNCTION__, interface_name);
        return RETURN_ERR;
    }

    ret = _syscmd(cmd, buf, sizeof(buf));
    if (ret == RETURN_ERR) {
        wifi_dbg_printf("%s: failed to execute '%s' for %s\n", __FUNCTION__, cmd, interface_name);
        return RETURN_ERR;
    }

    *output_array_size = count_occurences(buf, "Station");
    if (*output_array_size == 0) return RETURN_OK;

    temp = calloc(*output_array_size, sizeof(wifi_associated_dev3_t));
    if (temp == NULL) {
        wifi_dbg_printf("%s: failed to allocate dev array for %s\n", __FUNCTION__, interface_name);
        return RETURN_ERR;
    }
    *associated_dev_array = temp;

    wifi_dbg_printf("%s: array_size = %u\n", __FUNCTION__, *output_array_size);
    ptr = get_line_from_str_buf(buf, line);
    i = -1;
    while (ptr) {
        if (strstr(line, "Station")) {
            i++;
            key = strtok(line, " ");
            val = strtok(NULL, " ");
            if (sscanf(val, "%02x:%02x:%02x:%02x:%02x:%02x",
                &temp[i].cli_MACAddress[0],
                &temp[i].cli_MACAddress[1],
                &temp[i].cli_MACAddress[2],
                &temp[i].cli_MACAddress[3],
                &temp[i].cli_MACAddress[4],
                &temp[i].cli_MACAddress[5]) != MACADDRESS_SIZE) {
                    wifi_dbg_printf("%s: failed to parse MAC of client connected to %s\n", __FUNCTION__, interface_name);
                    free(*associated_dev_array);
                    return RETURN_ERR;
            }
        }
        else if (i < 0) {
            ptr = get_line_from_str_buf(ptr, line);
            continue; // We didn't detect 'station' entry yet
        }
        else if (strstr(line, "signal avg")) {
            key = strtok(line, ":");
            val = strtok(NULL, " ");
            if (sscanf(val, "%d", &rssi) <= 0 ) {
                wifi_dbg_printf("%s: failed to parse RSSI of client connected to %s\n", __FUNCTION__, interface_name);
                free(*associated_dev_array);
                return RETURN_ERR;
            }
            temp[i].cli_RSSI = rssi;
            temp[i].cli_SNR = 95 + rssi; // We use constant -95 noise floor
        }
        // Here other fields can be parsed if added to filter of 'iw dev' command

        ptr = get_line_from_str_buf(ptr, line);
    };

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

#if 0
//To-do
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    //Using different approach to get required WiFi Parameters from system available commands
#if 0 
    FILE *f;
    int read_flag=0, auth_temp=0, mac_temp=0,i=0;
    char cmd[256], buf[2048];
    char *param , *value, *line=NULL;
    size_t len = 0;
    ssize_t nread;
    wifi_associated_dev3_t *dev=NULL;
    *associated_dev_array = NULL;
    sprintf(cmd, "hostapd_cli -i%s%d all_sta | grep AUTHORIZED | wc -l", AP_PREFIX, apIndex);
    _syscmd(cmd,buf,sizeof(buf));
    *output_array_size = atoi(buf);

    if (*output_array_size <= 0)
        return RETURN_OK;

    dev=(wifi_associated_dev3_t *) AnscAllocateMemory(*output_array_size * sizeof(wifi_associated_dev3_t));
    *associated_dev_array = dev;
    sprintf(cmd, "hostapd_cli -i%s%d all_sta > /tmp/connected_devices.txt", AP_PREFIX, apIndex);
    _syscmd(cmd,buf,sizeof(buf));
    f = fopen("/tmp/connected_devices.txt", "r");
    if (f==NULL)
    {
        *output_array_size=0;
        return RETURN_ERR;
    }
    while ((nread = getline(&line, &len, f)) != -1)
    {
        param = strtok(line,"=");
        value = strtok(NULL,"=");

        if( strcmp("flags",param) == 0 )
        {
            value[strlen(value)-1]='\0';
            if(strstr (value,"AUTHORIZED") != NULL )
            {
                dev[auth_temp].cli_AuthenticationState = 1;
                dev[auth_temp].cli_Active = 1;
                auth_temp++;
                read_flag=1;
            }
        }
        if(read_flag==1)
        {
            if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
            {
                value[strlen(value)-1]='\0';
                sscanf(value, "%x:%x:%x:%x:%x:%x",
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[0],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[1],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[2],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[3],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[4],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[5] );

            }
            else if( strcmp("rx_packets",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_PacketsReceived));
            }

            else if( strcmp("tx_packets",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_PacketsSent));				
            }

            else if( strcmp("rx_bytes",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_BytesReceived));
            }

            else if( strcmp("tx_bytes",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_BytesSent));		
                mac_temp++;
                read_flag=0;
            }						
        }
    }

    *output_array_size = auth_temp;
    auth_temp=0;
    mac_temp=0;
    free(line);
    fclose(f);
#endif
    char interface_name[MAX_BUF_SIZE] = {0};
    char wifi_status[MAX_BUF_SIZE] = {0};
    char hostapdconf[MAX_BUF_SIZE] = {0};

    wifi_associated_dev3_t *dev_array = NULL;
    ULONG wifi_count = 0;

    *associated_dev_array = NULL;
    *output_array_size = 0;

    printf("wifi_getApAssociatedDeviceDiagnosticResult3 apIndex = %d \n", apIndex);
    //if(apIndex == 0 || apIndex == 1 || apIndex == 4 || apIndex == 5) // These are availble in RPI.
    {
        sprintf(hostapdconf, "/nvram/hostapd%d.conf", apIndex);

        GetInterfaceName(interface_name, hostapdconf);

        if(strlen(interface_name) > 1)
        {
            wifihal_interfacestatus(wifi_status,interface_name);
            if(strcmp(wifi_status,"RUNNING") == 0)
            {
                wifihal_AssociatedDevicesstats3(apIndex,interface_name,&dev_array,&wifi_count);

                *associated_dev_array = dev_array;
                *output_array_size = wifi_count;		
            }
            else
            {
                *associated_dev_array = NULL;
            }
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#endif

/* getIPAddress function */
/**
* @description Returning IpAddress of the Matched String
*
* @param 
* @str Having MacAddress
* @ipaddr Having ipaddr 
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT getIPAddress(char *str,char *ipaddr)
{
    FILE *fp = NULL;
    char buf[1024] = {0},ipAddr[50] = {0},phyAddr[100] = {0},hostName[100] = {0};
    int LeaseTime = 0,ret = 0;
    if ( (fp=fopen("/nvram/dnsmasq.leases", "r")) == NULL )
    {
        return RETURN_ERR;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        /*
        Sample:sss
        1560336751 00:cd:fe:f3:25:e6 10.0.0.153 NallamousiPhone 01:00:cd:fe:f3:25:e6
        1560336751 12:34:56:78:9a:bc 10.0.0.154 NallamousiPhone 01:00:cd:fe:f3:25:e6
        */
        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
                 &(LeaseTime),
                 phyAddr,
                 ipAddr,
                 hostName
              );
        if(ret != 4)
            continue;
        if(strcmp(str,phyAddr) == 0)
                strcpy(ipaddr,ipAddr);
    }
    return RETURN_OK;
}

/* wifi_getApInactiveAssociatedDeviceDiagnosticResult function */
/**
* @description Returning Inactive wireless connected clients informations
*
* @param 
* @filename Holding private_wifi 2g/5g content files
* @associated_dev_array  Having inactiv wireless clients informations
* @output_array_size Returning Inactive wireless counts
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT wifi_getApInactiveAssociatedDeviceDiagnosticResult(char *filename,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    int count = 0,maccount = 0,i = 0,wificlientindex = 0;
    FILE *fp = NULL;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    char path[1024] = {0},str[1024] = {0},ipaddr[50] = {0},buf[512] = {0};
    sprintf(buf,"cat %s | grep Station | sort | uniq | wc -l",filename);
    fp = popen(buf,"r");
    if(fp == NULL)
        return RETURN_ERR;
    else
    {
        fgets(path,sizeof(path),fp);
        maccount = atoi(path);
    }
    pclose(fp);
    *output_array_size = maccount;
    wifi_associated_dev3_t* temp = NULL;
    temp = (wifi_associated_dev3_t *) calloc (*output_array_size, sizeof(wifi_associated_dev3_t));
    *associated_dev_array = temp;
    if(temp == NULL)
    {
        printf("Error Statement. Insufficient memory \n");
        return RETURN_ERR;
    }
    memset(buf,0,sizeof(buf));
    sprintf(buf,"cat %s | grep Station | cut -d ' ' -f2 | sort | uniq",filename);
    fp = popen(buf,"r");
    for(count = 0; count < maccount ; count++)
    {
        fgets(path,sizeof(path),fp);
        for(i = 0; path[i]!='\n';i++)
            str[i]=path[i];
        str[i]='\0';
        getIPAddress(str,ipaddr);
        memset(buf,0,sizeof(buf));
        if(strlen(ipaddr) > 0)
        {
            sprintf(buf,"ping -q -c 1 -W 1  \"%s\"  > /dev/null 2>&1",ipaddr);
            if (WEXITSTATUS(system(buf)) != 0)  //InActive wireless clients info
            {
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_AuthenticationState = 0; //TODO
                temp[count].cli_Active = 0; //TODO      
                temp[count].cli_SignalStrength = 0;
            }
            else //Active wireless clients info
            {
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_Active = 1;
            }
        }
        memset(ipaddr,0,sizeof(ipaddr));
    }
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering object
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Capability bool r/o
//To get Band Steering Capability
INT wifi_getBandSteeringCapability(BOOL *support)
{
    *support = FALSE;
    return RETURN_OK;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable bool r/w
//To get Band Steering enable status
INT wifi_getBandSteeringEnable(BOOL *enable)
{
    *enable = FALSE;
    return RETURN_OK;
}

//To turn on/off Band steering
INT wifi_setBandSteeringEnable(BOOL enable)
{
    return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.APGroup string r/w
//To get Band Steering AP group
INT wifi_getBandSteeringApGroup(char *output_ApGroup)
{
    if (NULL == output_ApGroup)
        return RETURN_ERR;

    strcpy(output_ApGroup, "1,2");
    return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.UtilizationThreshold int r/w
//to set and read the band steering BandUtilizationThreshold parameters
INT wifi_getBandSteeringBandUtilizationThreshold (INT radioIndex, INT *pBuThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringBandUtilizationThreshold (INT radioIndex, INT buThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.RSSIThreshold int r/w
//to set and read the band steering RSSIThreshold parameters
INT wifi_getBandSteeringRSSIThreshold (INT radioIndex, INT *pRssiThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringRSSIThreshold (INT radioIndex, INT rssiThreshold)
{
    return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.PhyRateThreshold int r/w
//to set and read the band steering physical modulation rate threshold parameters
INT wifi_getBandSteeringPhyRateThreshold (INT radioIndex, INT *pPrThreshold)
{
    //If chip is not support, return -1
    return RETURN_ERR;
}

INT wifi_setBandSteeringPhyRateThreshold (INT radioIndex, INT prThreshold)
{
    //If chip is not support, return -1
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.OverloadInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under overload condition
INT wifi_getBandSteeringOverloadInactiveTime(INT radioIndex, INT *pPrThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringOverloadInactiveTime(INT radioIndex, INT prThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.IdleInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under Idle condition
INT wifi_getBandSteeringIdleInactiveTime(INT radioIndex, INT *pPrThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringIdleInactiveTime(INT radioIndex, INT prThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.History string r/o
//pClientMAC[64]
//pSourceSSIDIndex[64]
//pDestSSIDIndex[64]
//pSteeringReason[256]
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason)
{
    //if no steering or redord_index is out of boundary, return -1. pSteeringTime returns the UTC time in seconds. pClientMAC is pre allocated as 64bytes. pSteeringReason returns the predefined steering trigger reason
    *pSteeringTime=time(NULL);
    *pSteeringReason = 0; //TODO: need to assign correct steering reason (INT numeric, i suppose)
    return RETURN_OK;
}

INT wifi_ifConfigDown(INT apIndex)
{
  INT status = RETURN_OK;
  char cmd[64];

  snprintf(cmd, sizeof(cmd), "ifconfig ath%d down", apIndex);
  printf("%s: %s\n", __func__, cmd);
  system(cmd);

  return status;
}

INT wifi_ifConfigUp(INT apIndex)
{
    char cmd[128];
    char buf[1024];

    snprintf(cmd, sizeof(cmd), "ifconfig %s%d up 2>/dev/null", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    return 0;
}

//>> Deprecated. Replace with wifi_applyRadioSettings
INT wifi_pushBridgeInfo(INT apIndex)
{
    char ip[32];
    char subnet[32];
    char bridge[32];
    int vlanId;
    char cmd[128];
    char buf[1024];

    wifi_getApBridgeInfo(apIndex,bridge,ip,subnet);
    wifi_getApVlanID(apIndex,&vlanId);

    snprintf(cmd, sizeof(cmd), "cfgVlan %s%d %s %d %s ", AP_PREFIX, apIndex, bridge, vlanId, ip);
    _syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannel(INT radioIndex, UINT channel)
{
    char cmd[128];
    char buf[1024];
    int  apIndex;

    apIndex=(radioIndex==0)?0:1;	
    snprintf(cmd, sizeof(cmd), "iwconfig %s%d freq %d",AP_PREFIX, apIndex,channel);
    _syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannelMode(INT radioIndex)
{
    //Apply Channel mode, pure mode, etc that been set by wifi_setRadioChannelMode() instantly
    return RETURN_ERR;
}

INT wifi_pushDefaultValues(INT radioIndex)
{
    //Apply Comcast specified default radio settings instantly
    //AMPDU=1
    //AMPDUFrames=32
    //AMPDULim=50000
    //txqueuelen=1000

    return RETURN_ERR;
}

INT wifi_pushTxChainMask(INT radioIndex)
{
    //Apply default TxChainMask instantly
    return RETURN_ERR;
}

INT wifi_pushRxChainMask(INT radioIndex)
{
    //Apply default RxChainMask instantly
    return RETURN_ERR;
}

INT wifi_pushSSID(INT apIndex, CHAR *ssid)
{
    INT status;

    status = wifi_setSSIDName(apIndex,ssid);
    wifi_setApEnable(apIndex,FALSE);
    wifi_setApEnable(apIndex,TRUE);

    return status;
}

INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
    //Apply default Ssid Advertisement instantly
    return RETURN_ERR;
}

INT wifi_getRadioUpTime(INT radioIndex, ULONG *output)
{
    INT status = RETURN_ERR;
    *output = 0;
    return RETURN_ERR;
}

INT wifi_getApEnableOnLine(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int)
{
   return RETURN_OK;
}

//To-do
INT wifi_getApSecurityMFPConfig(INT apIndex, CHAR *output_string)
{
    return RETURN_OK;
}
INT wifi_setApSecurityMFPConfig(INT apIndex, CHAR *MfpConfig)
{
    return RETURN_OK;
}
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)
{
    char output[16]={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_hostapdRead(radioIndex, "channel", output, sizeof(output));

    *output_bool = (strncmp(output, "0", 1)==0) ?  TRUE : FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getRouterEnable(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT *rekeyInterval)
{
   return RETURN_OK;
}

INT wifi_setRouterEnable(INT wlanIndex, INT *RouterEnabled)
{
   return RETURN_OK;
}

INT wifi_getRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (NULL == output)
        return RETURN_ERR;
    wifi_hostapdRead(wlanIndex,"hw_mode",output,64);

    if(strcmp(output,"b")==0)
        sprintf(output, "%s", "1,2,5.5,11");
    else if (strcmp(output,"a")==0)
        sprintf(output, "%s", "6,9,11,12,18,24,36,48,54");
    else if ((strcmp(output,"n")==0) | (strcmp(output,"g")==0))
        sprintf(output, "%s", "1,2,5.5,6,9,11,12,18,24,36,48,54");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *temp;
    char temp_output[128];
    char temp_TransmitRates[128];

    if (NULL == output)
        return RETURN_ERR;

    wifi_hostapdRead(wlanIndex,"supported_rates",output,64);

    strcpy(temp_TransmitRates,output);
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        temp[strlen(temp)-1]=0;
        if((temp[0]=='5') && (temp[1]=='\0'))
        {
            temp="5.5";
        }
        strcat(temp_output,temp);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output,",");
        }
    }
    strcpy(output,temp_output);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
        return RETURN_OK;
}


INT wifi_setRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    int i=0;
    char *temp;
    char temp1[128];
    char temp_output[128];
    char temp_TransmitRates[128];
    struct params params={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == output)
        return RETURN_ERR;

    strcpy(temp_TransmitRates,output);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) | (temp_TransmitRates[i]==' ') | (temp_TransmitRates[i]=='.'))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(wlanIndex==1)
        {
            if((strcmp(temp,"1")==0) | (strcmp(temp,"2")==0) | (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }

        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(output,temp_output);


    params.name = "supported_rates";
    params.value = output;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("params.value=%s\n",params.value);
    wifi_hostapdWrite(wlanIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}


static char *sncopy(char *dst, int dst_sz, const char *src)
{
    if (src && dst && dst_sz > 0) {
        strncpy(dst, src, dst_sz);
        dst[dst_sz - 1] = '\0';
    }
    return dst;
}

static int util_get_sec_chan_offset(int channel, const char* ht_mode)
{
    if (0 == strcmp(ht_mode, "HT40") ||
        0 == strcmp(ht_mode, "HT80") ||
        0 == strcmp(ht_mode, "HT160")) {
        switch (channel) {
            case 1 ... 7:
            case 36:
            case 44:
            case 52:
            case 60:
            case 100:
            case 108:
            case 116:
            case 124:
            case 132:
            case 140:
            case 149:
            case 157:
                return 1;
            case 8 ... 13:
            case 40:
            case 48:
            case 56:
            case 64:
            case 104:
            case 112:
            case 120:
            case 128:
            case 136:
            case 144:
            case 153:
            case 161:
                return -1;
            default:
                return -EINVAL;
        }
    }

    return -EINVAL;
}

static void util_hw_mode_to_bw_mode(const char* hw_mode, char *bw_mode, int bw_mode_len)
{
    if (NULL == hw_mode) return;

    if (0 == strcmp(hw_mode, "ac"))
        sncopy(bw_mode, bw_mode_len, "ht vht");

    if (0 == strcmp(hw_mode, "n"))
        sncopy(bw_mode, bw_mode_len, "ht");

    return;
}

static int util_chan_to_freq(int chan)
{
    if (chan == 14)
        return 2484;
    else if (chan < 14)
        return 2407 + chan * 5;
    else if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
    else
        return 5000 + chan * 5;
    return 0;
}

const int *util_unii_5g_chan2list(int chan, int width)
{
    static const int lists[] = {
        // <width>, <chan1>, <chan2>..., 0,
        20, 36, 0,
        20, 40, 0,
        20, 44, 0,
        20, 48, 0,
        20, 52, 0,
        20, 56, 0,
        20, 60, 0,
        20, 64, 0,
        20, 100, 0,
        20, 104, 0,
        20, 108, 0,
        20, 112, 0,
        20, 116, 0,
        20, 120, 0,
        20, 124, 0,
        20, 128, 0,
        20, 132, 0,
        20, 136, 0,
        20, 140, 0,
        20, 144, 0,
        20, 149, 0,
        20, 153, 0,
        20, 157, 0,
        20, 161, 0,
        20, 165, 0,
        40, 36, 40, 0,
        40, 44, 48, 0,
        40, 52, 56, 0,
        40, 60, 64, 0,
        40, 100, 104, 0,
        40, 108, 112, 0,
        40, 116, 120, 0,
        40, 124, 128, 0,
        40, 132, 136, 0,
        40, 140, 144, 0,
        40, 149, 153, 0,
        40, 157, 161, 0,
        80, 36, 40, 44, 48, 0,
        80, 52, 56, 60, 64, 0,
        80, 100, 104, 108, 112, 0,
        80, 116, 120, 124, 128, 0,
        80, 132, 136, 140, 144, 0,
        80, 149, 153, 157, 161, 0,
        160, 36, 40, 44, 48, 52, 56, 60, 64, 0,
        160, 100, 104, 108, 112, 116, 120, 124, 128, 0,
        -1 // final delimiter
    };
    const int *start;
    const int *p;

    for (p = lists; *p != -1; p++) {
        if (*p == width) {
            for (start = ++p; *p != 0; p++) {
                if (*p == chan)
                    return start;
            }
        }
        // move to the end of channel list of given width
        while (*p != 0) {
            p++;
        }
    }

    return NULL;
}

static int util_unii_5g_centerfreq(const char *ht_mode, int channel)
{
    if (NULL == ht_mode)
        return 0;

    const int width = atoi(strlen(ht_mode) > 2 ? ht_mode + 2 : "20");
    const int *chans = util_unii_5g_chan2list(channel, width);
    int sum = 0;
    int cnt = 0;

    if (NULL == chans)
        return 0;

    while (*chans) {
        sum += *chans;
        cnt++;
        chans++;
    }
    return sum / cnt;
}

static int util_radio_get_hw_mode(int radioIndex, char *hw_mode, int hw_mode_size)
{
    BOOL onlyG, onlyN, onlyA;
    CHAR tmp[64];
    int ret = wifi_getRadioStandard(radioIndex, tmp, &onlyG, &onlyN, &onlyA);
    if (ret == RETURN_OK) {
        sncopy(hw_mode, hw_mode_size, tmp);
    }
    return ret;
}

INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count)
{
    // Sample commands:
    //   hostapd_cli -i wifi1 chan_switch 30 5200 sec_channel_offset=-1 center_freq1=5190 bandwidth=40 ht vht
    //   hostapd_cli -i wifi0 chan_switch 30 2437
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    int freq = 0, ret = 0;
    char center_freq1_str[32] = ""; // center_freq1=%d
    char opt_chan_info_str[32] = ""; // bandwidth=%d ht vht
    char sec_chan_offset_str[32] = ""; // sec_channel_offset=%d
    char hw_mode[16] = ""; // n|ac
    char bw_mode[16] = ""; // ht|ht vht
    char ht_mode[16] = ""; // HT20|HT40|HT80|HT160
    int sec_chan_offset;
    int width;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    freq = util_chan_to_freq(channel);

    // Get radio mode HT20|HT40|HT80 etc.
    width = channel_width_MHz > 20 ? channel_width_MHz : 20;
    snprintf(ht_mode, sizeof(ht_mode), "HT%d", width);
    // Find channel offset +1/-1 for wide modes (HT40|HT80|HT160)
    sec_chan_offset = util_get_sec_chan_offset(channel, ht_mode);
    if (sec_chan_offset != -EINVAL)
        snprintf(sec_chan_offset_str, sizeof(sec_chan_offset_str), "sec_channel_offset=%d", sec_chan_offset);


    // Provide bandwith if specified
    if (channel_width_MHz > 20) {
        // Select bandwidth mode from hardware n --> ht | ac --> ht vht
        util_radio_get_hw_mode(radioIndex, hw_mode, sizeof(hw_mode));
        util_hw_mode_to_bw_mode(hw_mode, bw_mode, sizeof(bw_mode));

        snprintf(opt_chan_info_str, sizeof(opt_chan_info_str), "bandwidth=%d %s", width, bw_mode);
    }

    int center_chan = 0;
    if (channel_width_MHz > 20) {
        center_chan = util_unii_5g_centerfreq(ht_mode, channel);
        if (center_chan > 0) {
            int center_freq1 = util_chan_to_freq(center_chan);
            if (center_freq1)
                snprintf(center_freq1_str, sizeof(center_freq1_str), "center_freq1=%d", center_freq1);
        }
    }

    {
	// Only the first AP, other are hanging on the same radio
	int apIndex = radioIndex;
        snprintf(cmd, sizeof(cmd), "hostapd_cli  -i %s%d chan_switch %d %d %s %s %s",
            AP_PREFIX, apIndex, csa_beacon_count, freq,
            sec_chan_offset_str, center_freq1_str, opt_chan_info_str);
        wifi_dbg_printf("execute: '%s'\n", cmd);
        ret = _syscmd(cmd, buf, sizeof(buf));
    }

    wifi_setRadioChannel(radioIndex, channel);

    char *ext_str = "None";
    if (sec_chan_offset == 1) ext_str = "Above";
    else if (sec_chan_offset == -1) ext_str = "Below";
    wifi_setRadioExtChannel(radioIndex, ext_str);

    wifi_setRadioCenterChannel(radioIndex, center_chan);

    char mhz_str[16];
    snprintf(mhz_str, sizeof(mhz_str), "%dMHz", width);
    wifi_setRadioOperatingChannelBandwidth(radioIndex, mhz_str);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    char cmd[1024] =  {0};
    char buf[1024] = {0};
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_neighbor_ap2_t *scan_array = NULL;
    int scan_count=0;
    int i =0;
    int freq=0;
    size_t len=0;
    FILE *f = NULL;
    ssize_t read = 0;
    char *line =NULL;
    char radio_ifname[64];
    char secondary_chan[64];
    int vht_channel_width = 0;

    if(wifi_getRadioIfName(radio_index,radio_ifname)!=RETURN_OK)
        return RETURN_ERR;

    /* sched_start is not supported on open source ath9k ath10k firmware
     * Using active scan as a workaround */
    sprintf(cmd,"iw dev %s scan |grep '^BSS\\|SSID:\\|freq:\\|signal:\\|HT operation:\\|secondary channel offset:\\|* channel width:'", radio_ifname);
    if((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }
    read = getline(&line, &len, f);
    while (read  != -1) {
        if(strncmp(line,"BSS",3) == 0) {
            i = scan_count;
            scan_count++;
            scan_array = realloc(scan_array,sizeof(wifi_neighbor_ap2_t)*scan_count);
            memset(&(scan_array[i]),0, sizeof(wifi_neighbor_ap2_t));
            sscanf(line,"BSS %17s", scan_array[i].ap_BSSID);

            read = getline(&line, &len, f);
            sscanf(line,"	freq: %d", &freq);
            scan_array[i].ap_Channel = ieee80211_frequency_to_channel(freq);

            read = getline(&line, &len, f);
            sscanf(line,"	signal: %d", &(scan_array[i].ap_SignalStrength));

            read = getline(&line, &len, f);
            sscanf(line,"	SSID: %s", scan_array[i].ap_SSID);
            wifi_dbg_printf("%s:Discovered BSS %s, %d, %d , %s\n", __func__, scan_array[i].ap_BSSID, scan_array[i].ap_Channel,scan_array[i].ap_SignalStrength, scan_array[i].ap_SSID);
            read = getline(&line, &len, f);
            if(strncmp(line,"BSS",3)==0) {
                // No HT and no VHT => 20Mhz
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11%s", radio_index%1 ? "A": "G");
                wifi_dbg_printf("%s: ap_OperatingChannelBandwidth = '%s'\n", __func__, scan_array[i].ap_OperatingChannelBandwidth);
                continue;
            }
            if(strncmp(line,"	HT operation:",14)!= 0) {
                    wifi_dbg_printf("HT output parsing error (%s)\n", line);
                    goto output_error;
            }

            read = getline(&line, &len, f);
            sscanf(line,"		 * secondary channel offset: %s", &secondary_chan);

            if(!strcmp(secondary_chan, "no")) {
                //20Mhz
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11N%s_HT20", radio_index%1 ? "A": "G");
            }

            if(!strcmp(secondary_chan, "above")) {
                //40Mhz +
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11N%s_HT40PLUS", radio_index%1 ? "A": "G");
            }

            if(!strcmp(secondary_chan, "below")) {
                //40Mhz -
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11N%s_HT40MINUS", radio_index%1 ? "A": "G");
            }


            read = getline(&line, &len, f);
            if(strncmp(line,"	VHT operation:",15) !=0) {
                wifi_dbg_printf("%s: ap_OperatingChannelBandwidth = '%s'\n", __func__, scan_array[i].ap_OperatingChannelBandwidth);
                // No VHT
                continue;
            }
            read = getline(&line, &len, f);
            sscanf(line,"		 * channel width: %d", &vht_channel_width);
            if(vht_channel_width == 1) {
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11AC_VHT80");
            } else {
                snprintf(scan_array[i].ap_OperatingChannelBandwidth, sizeof(scan_array[i].ap_OperatingChannelBandwidth), "11AC_VHT40");
            }

        }
        wifi_dbg_printf("%s: ap_OperatingChannelBandwidth = '%s'\n", __func__, scan_array[i].ap_OperatingChannelBandwidth);
        read = getline(&line, &len, f);
    }
    wifi_dbg_printf("%s:Counted BSS: %d\n",__func__, scan_count);
    *output_array_size = scan_count;
    *neighbor_ap_array = scan_array;
    free(line);
    pclose(f);
    return RETURN_OK;

output_error:
    pclose(f);
    free(line);
    free(scan_array);
    return RETURN_ERR;
}
INT wifi_getApAssociatedDeviceStats(
        INT apIndex,
        mac_address_t *clientMacAddress,
        wifi_associated_dev_stats_t *associated_dev_stats,
        u64 *handle)
{
    wifi_associated_dev_stats_t *dev_stats = associated_dev_stats;
    char interface_name[50] = {0};
    char cmd[1024] =  {0};
    char mac_str[18] = {0};
    char *key = NULL;
    char *val = NULL;
    FILE *f = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;

    if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    sprintf(mac_str, "%x:%x:%x:%x:%x:%x", (*clientMacAddress)[0],(*clientMacAddress)[1],(*clientMacAddress)[2],(*clientMacAddress)[3],(*clientMacAddress)[4],(*clientMacAddress)[5]);
    sprintf(cmd,"iw dev %s station get %s | grep 'rx\\|tx' | tr -d '\t'", interface_name, mac_str);
    if((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }

    while ((read = getline(&line, &len, f))  != -1) {
        key = strtok(line,":");
        val = strtok(NULL,":");

	if(!strncmp(key,"rx bytes",8))
	    sscanf(val, "%llu", &dev_stats->cli_rx_bytes);
	if(!strncmp(key,"tx bytes",8))
            sscanf(val, "%llu", &dev_stats->cli_tx_bytes);
	if(!strncmp(key,"rx packets",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_frames);
	if(!strncmp(key,"tx packets",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_frames);
        if(!strncmp(key,"tx retries",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_retries);
        if(!strncmp(key,"tx failed",9))
            sscanf(val, "%llu", &dev_stats->cli_tx_errors);
        if(!strncmp(key,"rx drop misc",13))
            sscanf(val, "%llu", &dev_stats->cli_rx_errors);
        if(!strncmp(key,"rx bitrate",10)) {
            val = strtok(val, " ");
            sscanf(val, "%lf", &dev_stats->cli_rx_rate);
        }
        if(!strncmp(key,"tx bitrate",10)) {
            val = strtok(val, " ");
            sscanf(val, "%lf", &dev_stats->cli_tx_rate);
        }
    }
    free(line);
    pclose(f);
    return RETURN_OK;
}

INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string)
{
    char cmd[MAX_CMD_SIZE] = {0}, buf[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli  -i %s%d get_config | grep ^ssid | cut -d '=' -f2 | tr -d '\n'", AP_PREFIX,apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    //size of SSID name restricted to value less than 32 bytes
    snprintf(output_string, 32, "%s", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode)
{
    char buf[32] = {0};

    if (!output_filterMode)
        return RETURN_ERR;

    //snprintf(cmd, sizeof(cmd), "syscfg get %dblockall", apIndex);
    //_syscmd(cmd, buf, sizeof(buf));
    wifi_hostapdRead(apIndex, "macaddr_acl", buf, sizeof(buf));
    *output_filterMode = atoi(buf);

    return RETURN_OK;
}

INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex,wifi_associated_dev2_t **associated_dev_array,UINT *output_array_size)
{
    FILE *fp = NULL;
    char str[MAX_BUF_SIZE] = {0};
    int wificlientindex = 0 ;
    int count = 0;
    int signalstrength = 0;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    UINT wifi_count = 0;
    char virtual_interface_name[MAX_BUF_SIZE] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size = 0;
    *associated_dev_array = NULL;
    char interface_name[50] = {0};

    if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
    fp = popen(pipeCmd, "r");
    if (fp == NULL)
    {
        printf("Failed to run command inside function %s\n",__FUNCTION__ );
        return RETURN_ERR;
    }

    /* Read the output a line at a time - output it. */
    fgets(str, sizeof(str)-1, fp);
    wifi_count = (unsigned int) atoi ( str );
    *output_array_size = wifi_count;
    wifi_dbg_printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
    pclose(fp);

    if(wifi_count == 0)
    {
        return RETURN_OK;
    }
    else
    {
        wifi_associated_dev2_t* temp = NULL;
        temp = (wifi_associated_dev2_t*)calloc(wifi_count, sizeof(wifi_associated_dev2_t));
        *associated_dev_array = temp;
        if(temp == NULL)
        {
            printf("Error Statement. Insufficient memory \n");
            return RETURN_ERR;
        }

        snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
        system(pipeCmd);

        fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2", interface_name);
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            for(count =0 ; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    wifi_dbg_printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
            }
            pclose(fp);
        }

        //Updating  RSSI per client
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt", interface_name);
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
        if(fp)
        {
            for(count =0 ; count < wifi_count ;count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                signalstrength = atoi(str);
                temp[count].cli_RSSI = signalstrength;
            }
            pclose(fp);
        }


        //LastDataDownlinkRate
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt", interface_name);
        fp = popen(pipeCmd, "r");
        if (fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
        if (fp)
        {
            for (count = 0; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
                temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
            }
            pclose(fp);
        }

        //LastDataUplinkRate
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt", interface_name);
        fp = popen(pipeCmd, "r");
        if (fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
        if (fp)
        {
            for (count = 0; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
                temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
            }
            pclose(fp);
        }
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;

}

INT wifi_getSSIDTrafficStats2(INT ssidIndex,wifi_ssidTrafficStats2_t *output_struct)
{
#if 0
    /*char buf[1024] = {0};
    sprintf(cmd, "ifconfig %s%d ", AP_PREFIX, ssidIndex);
    _syscmd(cmd, buf, sizeof(buf));*/

    output_struct->ssid_BytesSent = 2048;   //The total number of bytes transmitted out of the interface, including framing characters.
    output_struct->ssid_BytesReceived = 4096;       //The total number of bytes received on the interface, including framing characters.
    output_struct->ssid_PacketsSent = 128;  //The total number of packets transmitted out of the interface.
    output_struct->ssid_PacketsReceived = 128; //The total number of packets received on the interface.

    output_struct->ssid_RetransCount = 0;   //The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two.
    output_struct->ssid_FailedRetransCount = 0; //The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012].
    output_struct->ssid_RetryCount = 0;  //The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012].
    output_struct->ssid_MultipleRetryCount = 0; //The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012].
    output_struct->ssid_ACKFailureCount = 0;  //The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012].
    output_struct->ssid_AggregatedPacketCount = 0; //The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac.

    output_struct->ssid_ErrorsSent = 0;     //The total number of outbound packets that could not be transmitted because of errors.
    output_struct->ssid_ErrorsReceived = 0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->ssid_UnicastPacketsSent = 2;     //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->ssid_UnicastPacketsReceived = 2;  //The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer.
    output_struct->ssid_DiscardedPacketsSent = 1; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->ssid_DiscardedPacketsReceived = 1; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->ssid_MulticastPacketsSent = 10; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_MulticastPacketsReceived = 0; //The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer.
    output_struct->ssid_BroadcastPacketsSent = 0;  //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_BroadcastPacketsRecevied = 1; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_UnknownPacketsReceived = 0;  //The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol.
#endif

    FILE *fp = NULL;
    char interface_name[50] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};
    char str[MAX_BUF_SIZE] = {0};
    wifi_ssidTrafficStats2_t *out = output_struct;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (!output_struct)
        return RETURN_ERR;

    if (ssidIndex >= 4)
        return RETURN_ERR;

    GetInterfaceName(ssidIndex, interface_name);
    sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | cut -d  ' ' -f11 | tr -d '\n'");
    fp = popen(pipeCmd, "r");
    fgets(str, MAX_BUF_SIZE,fp);
    out->ssid_BytesSent = atol(str);
    pclose(fp);

    sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | cut -d  ' ' -f3 | tr -d '\n'");
    fp = popen(pipeCmd, "r");
    fgets(str, MAX_BUF_SIZE,fp);
    out->ssid_BytesReceived = atol(str);
    pclose(fp);

    sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | cut -d  ' ' -f12 | tr -d '\n'");
    fp = popen(pipeCmd, "r");
    fgets(str, MAX_BUF_SIZE,fp);
    out->ssid_PacketsSent = atol(str);
    pclose(fp);

    sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | cut -d  ' ' -f4 | tr -d '\n'");
    fp = popen(pipeCmd, "r");
    fgets(str, MAX_BUF_SIZE,fp);
    out->ssid_PacketsReceived = atol(str);
    pclose(fp);
    /*
       //TODO:
       out->ssid_UnicastPacketsSent        = uni->ims_tx_data_packets;
       out->ssid_UnicastPacketsReceived    = uni->ims_rx_data_packets;
       out->ssid_MulticastPacketsSent      = multi->ims_tx_data_packets - multi->ims_tx_bcast_data_packets;
       out->ssid_MulticastPacketsReceived  = multi->ims_rx_data_packets - multi->ims_rx_bcast_data_packets;
       out->ssid_BroadcastPacketsSent      = multi->ims_tx_bcast_data_packets;
       out->ssid_BroadcastPacketsRecevied  = multi->ims_rx_bcast_data_packets; 
    */
    return RETURN_OK;
}

//Enables or disables device isolation. A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
    char output_val[16]={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (!output)
        return RETURN_ERR;
    wifi_hostapdRead(apIndex, "ap_isolate", output_val, sizeof(output_val));

    if( strcmp(output_val,"1") == 0 )
        *output = TRUE;
    else
        *output = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char str[MAX_BUF_SIZE]={'\0'};
    char string[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch;
    struct params params;

    if(enable == TRUE)
        strcpy(string,"1");
    else
        strcpy(string,"0");

    params.name = "ap_isolate";
    params.value = string;

    wifi_hostapdWrite(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
    if (NULL == output_dBm)
        return RETURN_ERR;

    *output_dBm = 0;
    return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT wlanIndex, INT dBm)
{
   return RETURN_OK;
}
INT wifi_getRadioDcsChannelMetrics(INT radioIndex,wifi_channelMetrics_t *input_output_channelMetrics_array,INT size)
{
   return RETURN_OK;
}
INT wifi_setRadioDcsDwelltime(INT radioIndex, INT ms)
{
    return RETURN_OK;
}
INT wifi_getRadioDcsDwelltime(INT radioIndex, INT *ms)
{
    return RETURN_OK;
}
INT wifi_setRadioDcsScanning(INT radioIndex, BOOL enable)
{
    return RETURN_OK;
}
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate)
{
    struct params list;

    list.name = "bss_transition";
    list.value = activate?"1":"0";
    wifi_hostapdWrite(apIndex, &list, 1);

    return RETURN_OK;
}
wifi_apAuthEvent_callback apAuthEvent_cb = NULL;

void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc)
{
    return;
}

INT wifi_setApCsaDeauth(INT apIndex, INT mode)
{
    // TODO Implement me!
    return RETURN_OK;
}

INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid)
{
    // TODO Implement me!
    return RETURN_OK;
}

INT wifi_pushRadioChannel(INT radioIndex, UINT channel)
{
    // TODO Implement me!
    //Apply wifi_pushRadioChannel() instantly
    return RETURN_ERR;
}

INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable)
{
    // TODO Implement me!
    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int tidStats_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1],*tidattr;
    int rem , tid_index = 0;

    wifi_associated_dev_tid_stats_t *out = (wifi_associated_dev_tid_stats_t*)arg;
    wifi_associated_dev_tid_entry_t *stats_entry;

    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                 [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED },
    };
    static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
                 [NL80211_TID_STATS_TX_MSDU] = { .type = NLA_U64 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);


    if (!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "station stats missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                             tb[NL80211_ATTR_STA_INFO],
                             stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    nla_for_each_nested(tidattr, sinfo[NL80211_STA_INFO_TID_STATS], rem)
    {
        stats_entry = &out->tid_array[tid_index];

        stats_entry->tid = tid_index;
        stats_entry->ac = _tid_ac_index_get[tid_index];

        if(sinfo[NL80211_STA_INFO_TID_STATS])
        {
            if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,tidattr, tid_policy)) {
                printf("failed to parse nested stats attributes!");
                return NL_SKIP;
            }
        }
        if(stats_info[NL80211_TID_STATS_TX_MSDU])
            stats_entry->num_msdus = (unsigned long long)nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

        if(tid_index < (PS_MAX_TID - 1))
            tid_index++;
    }
    //ToDo: sum_time_ms, ewma_time_ms
    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex,  mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats,  ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char  if_name[10];

    snprintf(if_name, sizeof(if_name), "%s%d", AP_PREFIX, radioIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
              NL_AUTO_PORT,
              NL_AUTO_SEQ,
              nl.id,
              0,
              0,
              NL80211_CMD_GET_STATION,
              0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,tidStats_callback,tid_stats);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
//iw implementation
#define TID_STATS_FILE "/tmp/tid_stats_file.txt"
#define TOTAL_MAX_LINES 50

    char buf[256] = {'\0'}; /* or other suitable maximum line size */
    char if_name[10];
    FILE *fp=NULL;
    char pipeCmd[1024]= {'\0'};
    int lines,tid_index=0;
    char mac_addr[20] = {'\0'};

    wifi_associated_dev_tid_entry_t *stats_entry;

    snprintf(if_name, sizeof(if_name), "%s%d", AP_PREFIX, radioIndex);
    strcpy(mac_addr,clientMacAddress);

    snprintf(pipeCmd,sizeof(pipeCmd),"iw dev %s station dump -v > "TID_STATS_FILE,if_name);
    fp= popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for station dump failed\n");
        return RETURN_ERR;
    }
    pclose(fp);

    snprintf(pipeCmd,sizeof(pipeCmd),"grep -n 'Station' "TID_STATS_FILE " | cut -d ':' -f1  | head -2 | tail -1");
    fp=popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for grep station failed\n");
        return RETURN_ERR;
    }
    else if(fgets(buf,sizeof(buf),fp) != NULL)
        lines=atoi(buf);
    else
    {
	pclose(fp);
        fprintf(stderr,"No devices are connected \n");
        return RETURN_ERR;
    }
    pclose(fp);

    if(lines == 1)
        lines = TOTAL_MAX_LINES; //only one client is connected , considering next MAX lines of iw output

    for(tid_index=0; tid_index<PS_MAX_TID; tid_index++)
    {
        stats_entry = &tid_stats->tid_array[tid_index];
        stats_entry->tid = tid_index;

        snprintf(pipeCmd, sizeof(pipeCmd),"cat "TID_STATS_FILE" | awk '/%s/ {for(i=0; i<=%d; i++) {getline; print}}'  |  grep -F -A%d 'MSDU'  | awk '{print $3}' | tail -1",mac_addr,lines,tid_index+2);

        fp=popen(pipeCmd,"r");
        if(fp ==NULL)
        {
            perror("Failed to read from tid file \n");
            return RETURN_ERR;
        }
        else if(fgets(buf,sizeof(buf),fp) != NULL)
            stats_entry->num_msdus = atol(buf);

        pclose(fp);
        stats_entry->ac = _tid_ac_index_get[tid_index];
//      TODO:
//      ULLONG ewma_time_ms;    <! Moving average value based on last couple of transmitted msdus
//      ULLONG sum_time_ms; <! Delta of cumulative msdus times over interval
    }
    return RETURN_OK;
#endif
}


INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    // TODO Implement me!
    return RETURN_OK;
}


INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventUnregister(void)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_delApAclDevices(INT apIndex)
{
    char cmd[MAX_BUF_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    char fname[100];
    FILE *fp;
    BOOL apEnabled = false;

    if(apIndex < 0 || apIndex >= MAX_APS)
        return RETURN_ERR;

    snprintf(fname, sizeof(fname), "%s%d", ACL_PREFIX, apIndex);
    fp = fopen(fname, "w");
    if (!fp) {
        return RETURN_ERR;
    }
    fclose(fp);

    wifi_getApEnable(apIndex, &apEnabled);
    if (apEnabled)
    {
        snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s%d accept_acl CLEAR", AP_PREFIX, apIndex);
        if(_syscmd(cmd,buf,sizeof(buf)))
            return RETURN_ERR;
    }

    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int rxStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
        NL80211_ATTR_MAX,
        genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0),
        NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy )) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return NL_SKIP;
    }

   if(sinfo[NL80211_STA_INFO_TID_STATS])
   {
       if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
           printf("failed to parse nested stats attributes!");
           return NL_SKIP;
       }
   }

   if( nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]) )
   {
       printf("Type is VHT\n");
       if(rinfo[NL80211_RATE_INFO_VHT_NSS])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

       if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 1;
       if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]) )
                         ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
  }
  else
  {
      printf(" OFDM or CCK \n");
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = 0;
  }

  if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
      if(rinfo[NL80211_RATE_INFO_MCS])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
      }
      if(sinfo[NL80211_STA_INFO_RX_BYTES64])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);
      else if (sinfo[NL80211_STA_INFO_RX_BYTES])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);

      if(stats_info[NL80211_TID_STATS_RX_MSDU])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_RX_MSDU]);

      if (sinfo[NL80211_STA_INFO_SIGNAL])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->rssi_combined = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
      //Assigning 0 for RETRIES ,PPDUS and MPDUS as we dont have rx retries attribute in libnl_3.3.0
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->retries = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->ppdus = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = 0;
      //rssi_array need to be filled
      return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[10];

    *output_array_size = sizeof(wifi_associated_dev_rate_info_rx_stats_t);

    if (*output_array_size <= 0)
        return RETURN_OK;

    snprintf(if_name, sizeof(if_name), "%s%d", AP_PREFIX, radioIndex);
    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
    fprintf(stderr, "Error initializing netlink \n");
    return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
        NL_AUTO_PORT,
        NL_AUTO_SEQ,
        nl.id,
        0,
        0,
        NL80211_CMD_GET_STATION,
        0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, *clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, rxStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

#ifdef HAL_NETLINK_IMPL
static int txStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return NL_SKIP;
    }

    if(sinfo[NL80211_STA_INFO_TID_STATS])
    {
        if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
            printf("failed to parse nested stats attributes!");
            return NL_SKIP;
        }
    }
    if(nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]))
    {
        printf("Type is VHT\n");
        if(rinfo[NL80211_RATE_INFO_VHT_NSS])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

        if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 1;
        if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]))
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
    }
    else
    {
        printf(" OFDM or CCK \n");
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = 0;
    }

    if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
       if(rinfo[NL80211_RATE_INFO_MCS])
           ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
    }

    if(sinfo[NL80211_STA_INFO_TX_BYTES64])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_TX_BYTES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

    //Assigning  0 for mpdus and ppdus , as we do not have attributes in netlink
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;

    if(stats_info[NL80211_TID_STATS_TX_MSDU])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

    if(sinfo[NL80211_STA_INFO_TX_RETRIES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);

    if(sinfo[NL80211_STA_INFO_TX_FAILED])
                 ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->attempts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]) + nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);

    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[10];

    *output_array_size = sizeof(wifi_associated_dev_rate_info_tx_stats_t);

    if (*output_array_size <= 0)
        return RETURN_OK;

    snprintf(if_name, sizeof(if_name), "%s%d", AP_PREFIX, radioIndex);

    nl.id = initSock80211(&nl);

    if(nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if(!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                0,
                NL80211_CMD_GET_STATION,
                0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, txStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate)
{
    // TODO Implement me!
    char buf[MAX_BUF_SIZE] = {0};

    wifi_hostapdRead(apIndex, "bss_transition", buf, sizeof(buf));
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;
}

INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
    struct params list;

    list.name = "rrm_neighbor_report";
    list.value = activate?"1":"0";
    wifi_hostapdWrite(apIndex, &list, 1);

    return RETURN_OK;
}

INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate)
{
    char buf[32] = {0};

    wifi_hostapdRead(apIndex, "rrm_neighbor_report", buf, sizeof(buf));
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;
}
#undef HAL_NETLINK_IMPL
#ifdef HAL_NETLINK_IMPL
static int chanSurveyInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
    char dev[20];
    int freq =0 ;
    static int i=0;

    wifi_channelStats_t_loc *out = (wifi_channelStats_t_loc*)arg;

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if (!tb[NL80211_ATTR_SURVEY_INFO]) {
        fprintf(stderr, "survey data missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,tb[NL80211_ATTR_SURVEY_INFO],survey_policy))
    {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }


    if(out[0].array_size == 1 )
    {
        if(sinfo[NL80211_SURVEY_INFO_IN_USE])
        {
            if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
                freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
            out[0].ch_number = ieee80211_frequency_to_channel(freq);

            if (sinfo[NL80211_SURVEY_INFO_NOISE])
                out[0].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
                out[0].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
                out[0].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
                out[0].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
                out[0].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME])
                out[0].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
            return NL_STOP;
        }
   }
   else
   {
       if ( i <=  out[0].array_size )
       {
           if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
               freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
           out[i].ch_number = ieee80211_frequency_to_channel(freq);

           if (sinfo[NL80211_SURVEY_INFO_NOISE])
               out[i].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
               out[i].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
               out[i].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
               out[i].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
               out[i].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME])
               out[i].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
      }
   }

   i++;
   return NL_SKIP;
}
#endif

static int ieee80211_channel_to_frequency(int channel, int *freqMHz)
{
    char command[MAX_CMD_SIZE], output[MAX_BUF_SIZE];
    FILE *fp;

    if(access("/tmp/freq-channel-map.txt", F_OK)==-1)
    {
        printf("Creating Frequency-Channel Map\n");
        system("iw phy | grep 'MHz \\[' | cut -d' ' -f2,4 > /tmp/freq-channel-map.txt");
    }
    snprintf(command, sizeof(command), "cat /tmp/freq-channel-map.txt | grep '\\[%d\\]$' | cut -d' ' -f1", channel);
    if((fp = popen(command, "r")))
    {
        fgets(output, sizeof(output), fp);
        *freqMHz = atoi(output);
        fclose(fp);
    }

    return 0;
}

static int get_survey_dump_buf(INT radioIndex, int channel, char *buf, size_t bufsz)
{
    int freqMHz = -1;
    char cmd[MAX_CMD_SIZE] = {'\0'};

    ieee80211_channel_to_frequency(channel, &freqMHz);
    if (freqMHz == -1) {
        wifi_dbg_printf("%s: failed to get channel frequency for channel: %d\n", __func__, channel);
        return -1;
    }

    if (sprintf(cmd,"iw dev %s%d survey dump | grep -A5 %d | tr -d '\\t'", RADIO_PREFIX, radioIndex, freqMHz) < 0) {
        wifi_dbg_printf("%s: failed to build iw dev command for radioIndex=%d freq=%d\n", __FUNCTION__,
                         radioIndex, freqMHz);
        return -1;
    }

    if (_syscmd(cmd, buf, bufsz) == RETURN_ERR) {
        wifi_dbg_printf("%s: failed to execute '%s' for radioIndex=%d\n", __FUNCTION__, cmd, radioIndex);
        return -1;
    }

    return 0;
}

static int fetch_survey_from_buf(INT radioIndex, const char *buf, wifi_channelStats_t *stats)
{
    const char *ptr = buf;
    char *key = NULL;
    char *val = NULL;
    char line[256] = { '\0' };

    while (ptr = get_line_from_str_buf(ptr, line)) {
        if (strstr(line, "Frequency")) continue;

        key = strtok(line, ":");
        val = strtok(NULL, " ");
        wifi_dbg_printf("%s: key='%s' val='%s'\n", __func__, key, val);

        if (!strcmp(key, "noise")) {
            sscanf(val, "%d", &stats->ch_noise);
            if (stats->ch_noise == 0) {
                // Workaround for missing noise information.
                // Assume -95 for 2.4G and -103 for 5G
                if (radioIndex == 0) stats->ch_noise = -95;
                if (radioIndex == 1) stats->ch_noise = -103;
            }
        }
        else if (!strcmp(key, "channel active time")) {
            sscanf(val, "%llu", &stats->ch_utilization_total);
        }
        else if (!strcmp(key, "channel busy time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy);
        }
        else if (!strcmp(key, "channel receive time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy_rx);
        }
        else if (!strcmp(key, "channel transmit time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy_tx);
        }
    };

    return 0;
}

INT wifi_getRadioChannelStats(INT radioIndex,wifi_channelStats_t *input_output_channelStats_array,INT array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    wifi_channelStats_t_loc local[array_size];
    char  if_name[10];

    local[0].array_size = array_size;

    snprintf(if_name, sizeof(if_name), "%s%d", AP_PREFIX, radioIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_SURVEY,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,chanSurveyInfo_callback,local);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    //Copying the Values
    for(int i=0;i<array_size;i++)
    {
        input_output_channelStats_array[i].ch_number = local[i].ch_number;
        input_output_channelStats_array[i].ch_noise = local[i].ch_noise;
        input_output_channelStats_array[i].ch_utilization_busy_rx = local[i].ch_utilization_busy_rx;
        input_output_channelStats_array[i].ch_utilization_busy_tx = local[i].ch_utilization_busy_tx;
        input_output_channelStats_array[i].ch_utilization_busy = local[i].ch_utilization_busy;
        input_output_channelStats_array[i].ch_utilization_busy_ext = local[i].ch_utilization_busy_ext;
        input_output_channelStats_array[i].ch_utilization_total = local[i].ch_utilization_total;
        //TODO: ch_radar_noise, ch_max_80211_rssi, ch_non_80211_noise, ch_utilization_busy_self
    }
#else
    ULONG channel = 0;
    int i;
    int number_of_channels = array_size;
    char buf[512];
    INT ret;
    wifi_channelStats_t tmp_stats;

    if (number_of_channels == 0) {
        if (wifi_getRadioChannel(radioIndex, &channel) != RETURN_OK) {
            wifi_dbg_printf("%s: cannot get current channel for radioIndex=%d\n", __func__, radioIndex);
            return RETURN_ERR;
        }
        number_of_channels = 1;
        input_output_channelStats_array[0].ch_number = channel;
    }

    for (i = 0; i < number_of_channels; i++) {

        input_output_channelStats_array[i].ch_noise = 0;
        input_output_channelStats_array[i].ch_utilization_busy_rx = 0;
        input_output_channelStats_array[i].ch_utilization_busy_tx = 0;
        input_output_channelStats_array[i].ch_utilization_busy = 0;
        input_output_channelStats_array[i].ch_utilization_busy_ext = 0; // XXX: unavailable
        input_output_channelStats_array[i].ch_utilization_total = 0;

        memset(buf, 0, sizeof(buf));
        if (get_survey_dump_buf(radioIndex, input_output_channelStats_array[i].ch_number, buf, sizeof(buf))) {
            return RETURN_ERR;
        }
        if (fetch_survey_from_buf(radioIndex, buf, &input_output_channelStats_array[i])) {
            wifi_dbg_printf("%s: cannot fetch survey from buf for radioIndex=%d\n", __func__, radioIndex);
            return RETURN_ERR;
        }

        // XXX: fake missing 'self' counter which is not available in iw survey output
        //      the 'self' counter (a.k.a 'bss') requires Linux Kernel update
        input_output_channelStats_array[i].ch_utilization_busy_self = input_output_channelStats_array[i].ch_utilization_busy_rx / 8;

        input_output_channelStats_array[i].ch_utilization_busy_rx *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy_tx *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy_self *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy *= 1000;
        input_output_channelStats_array[i].ch_utilization_total *= 1000;

        wifi_dbg_printf("%s: ch_number=%d ch_noise=%d total=%llu busy=%llu busy_rx=%llu busy_tx=%llu busy_self=%llu busy_ext=%llu\n",
                   __func__,
                   input_output_channelStats_array[i].ch_number,
                   input_output_channelStats_array[i].ch_noise,
                   input_output_channelStats_array[i].ch_utilization_total,
                   input_output_channelStats_array[i].ch_utilization_busy,
                   input_output_channelStats_array[i].ch_utilization_busy_rx,
                   input_output_channelStats_array[i].ch_utilization_busy_tx,
                   input_output_channelStats_array[i].ch_utilization_busy_self,
                   input_output_channelStats_array[i].ch_utilization_busy_ext);
    }
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#define HAL_NETLINK_IMPL

/* Hostapd events */

#ifndef container_of
#define offset_of(st, m) ((size_t)&(((st *)0)->m))
#define container_of(ptr, type, member) \
                   ((type *)((char *)ptr - offset_of(type, member)))
#endif /* container_of */

struct ctrl {
    char sockpath[128];
    char sockdir[128];
    char bss[IFNAMSIZ];
    char reply[4096];
    int ssid_index;
    void (*cb)(struct ctrl *ctrl, int level, const char *buf, size_t len);
    void (*overrun)(struct ctrl *ctrl);
    struct wpa_ctrl *wpa;
    unsigned int ovfl;
    size_t reply_len;
    int initialized;
    ev_timer retry;
    ev_timer watchdog;
    ev_stat stat;
    ev_io io;
};
static wifi_newApAssociatedDevice_callback clients_connect_cb;
static wifi_apDisassociatedDevice_callback clients_disconnect_cb;
static struct ctrl wpa_ctrl[MAX_APS];
static int initialized;

static unsigned int ctrl_get_drops(struct ctrl *ctrl)
{
    char cbuf[256] = {};
    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *cmsg;
    unsigned int ovfl = ctrl->ovfl;
    unsigned int drop;

    recvmsg(ctrl->io.fd, &msg, MSG_DONTWAIT);
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL)
            ovfl = *(unsigned int *)CMSG_DATA(cmsg);

    drop = ovfl - ctrl->ovfl;
    ctrl->ovfl = ovfl;

    return drop;
}

static void ctrl_close(struct ctrl *ctrl)
{
    if (ctrl->io.cb)
        ev_io_stop(EV_DEFAULT_ &ctrl->io);
    if (ctrl->retry.cb)
        ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
    if (!ctrl->wpa)
        return;

    wpa_ctrl_detach(ctrl->wpa);
    wpa_ctrl_close(ctrl->wpa);
    ctrl->wpa = NULL;
    printf("WPA_CTRL: closed index=%d\n", ctrl->ssid_index);
}

static void ctrl_process(struct ctrl *ctrl)
{
    const char *str;
    int drops;
    int level;
    int err;

    /* Example events:
     *
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19 keyid=sample_keyid
     * <3>AP-STA-DISCONNECTED 60:b4:f7:f0:0a:19
     * <3>CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
     * <3>CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
     */
    if (!(str = index(ctrl->reply, '>')))
        return;
    if (sscanf(ctrl->reply, "<%d>", &level) != 1)
        return;

    str++;

    if (strncmp("AP-STA-CONNECTED ", str, 17) == 0) {
        if (!(str = index(ctrl->reply, ' ')))
            return;
        wifi_associated_dev_t sta;
        memset(&sta, 0, sizeof(sta));

        sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &sta.cli_MACAddress[0], &sta.cli_MACAddress[1], &sta.cli_MACAddress[2],
                &sta.cli_MACAddress[3], &sta.cli_MACAddress[4], &sta.cli_MACAddress[5]);

        sta.cli_Active=true;

        (clients_connect_cb)(ctrl->ssid_index, &sta);
        goto handled;
    }

    if (strncmp("AP-STA-DISCONNECTED ", str, 20) == 0) {
        if (!(str = index(ctrl->reply, ' ')))
            return;

        (clients_disconnect_cb)(ctrl->ssid_index, (char*)str, 0);
        goto handled;
    }

    if (strncmp("CTRL-EVENT-TERMINATING", str, 22) == 0) {
        printf("CTRL_WPA: handle TERMINATING event\n");
        goto retry;
    }

    if (strncmp("AP-DISABLED", str, 11) == 0) {
        printf("CTRL_WPA: handle AP-DISABLED\n");
        goto retry;
    }

    printf("Event not supported!!\n");

handled:

    if ((drops = ctrl_get_drops(ctrl))) {
        printf("WPA_CTRL: dropped %d messages index=%d\n", drops, ctrl->ssid_index);
        if (ctrl->overrun)
            ctrl->overrun(ctrl);
    }

    return;

retry:
    printf("WPA_CTRL: closing\n");
    ctrl_close(ctrl);
    printf("WPA_CTRL: retrying from ctrl prcoess\n");
    ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

static void ctrl_ev_cb(EV_P_ struct ev_io *io, int events)
{
    struct ctrl *ctrl = container_of(io, struct ctrl, io);
    int err;

    memset(ctrl->reply, 0, sizeof(ctrl->reply));
    ctrl->reply_len = sizeof(ctrl->reply) - 1;
    err = wpa_ctrl_recv(ctrl->wpa, ctrl->reply, &ctrl->reply_len);
    ctrl->reply[ctrl->reply_len] = 0;
    if (err < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        ctrl_close(ctrl);
        ev_timer_again(EV_A_ &ctrl->retry);
        return;
    }

    ctrl_process(ctrl);
}

static int ctrl_open(struct ctrl *ctrl)
{
    int fd;

    if (ctrl->wpa)
        return 0;

    ctrl->wpa = wpa_ctrl_open(ctrl->sockpath);
    if (!ctrl->wpa)
        goto err;

    if (wpa_ctrl_attach(ctrl->wpa) < 0)
        goto err_close;

    fd = wpa_ctrl_get_fd(ctrl->wpa);
    if (fd < 0)
        goto err_detach;

    if (setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (int[]){1}, sizeof(int)) < 0)
        goto err_detach;

    ev_io_init(&ctrl->io, ctrl_ev_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &ctrl->io);

    return 0;

err_detach:
    wpa_ctrl_detach(ctrl->wpa);
err_close:
    wpa_ctrl_close(ctrl->wpa);
err:
    ctrl->wpa = NULL;
    return -1;
}

static void ctrl_stat_cb(EV_P_ ev_stat *stat, int events)
{
    struct ctrl *ctrl = container_of(stat, struct ctrl, stat);

    printf("WPA_CTRL: index=%d file state changed\n", ctrl->ssid_index);
    ctrl_open(ctrl);
}

static void ctrl_retry_cb(EV_P_ ev_timer *timer, int events)
{
    struct ctrl *ctrl = container_of(timer, struct ctrl, retry);

    printf("WPA_CTRL: index=%d retrying\n", ctrl->ssid_index);
    if (ctrl_open(ctrl) == 0) {
        printf("WPA_CTRL: retry successful\n");
        ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
    }
}

int ctrl_enable(struct ctrl *ctrl)
{
    if (ctrl->wpa)
        return 0;

    if (!ctrl->stat.cb) {
        ev_stat_init(&ctrl->stat, ctrl_stat_cb, ctrl->sockpath, 0.);
        ev_stat_start(EV_DEFAULT_ &ctrl->stat);
    }

    if (!ctrl->retry.cb) {
        ev_timer_init(&ctrl->retry, ctrl_retry_cb, 0., 5.);
    }

    return ctrl_open(ctrl);
}

static void
ctrl_msg_cb(char *buf, size_t len)
{
    struct ctrl *ctrl = container_of(buf, struct ctrl, reply);

    printf("WPA_CTRL: unsolicited message: index=%d len=%zu msg=%s", ctrl->ssid_index, len, buf);
    ctrl_process(ctrl);
}

static int ctrl_request(struct ctrl *ctrl, const char *cmd, size_t cmd_len, char *reply, size_t *reply_len)
{
    int err;

    if (!ctrl->wpa)
        return -1;
    if (*reply_len < 2)
        return -1;

    (*reply_len)--;
    ctrl->reply_len = sizeof(ctrl->reply);
    err = wpa_ctrl_request(ctrl->wpa, cmd, cmd_len, ctrl->reply, &ctrl->reply_len, ctrl_msg_cb);
    printf("WPA_CTRL: index=%d cmd='%s' err=%d\n", ctrl->ssid_index, cmd, err);
    if (err < 0)
        return err;

    if (ctrl->reply_len > *reply_len)
        ctrl->reply_len = *reply_len;

    *reply_len = ctrl->reply_len;
    memcpy(reply, ctrl->reply, *reply_len);
    reply[*reply_len - 1] = 0;
    printf("WPA_CTRL: index=%d reply='%s'\n", ctrl->ssid_index, reply);
    return 0;
}

static void ctrl_watchdog_cb(EV_P_ ev_timer *timer, int events)
{
    const char *pong = "PONG";
    const char *ping = "PING";
    char reply[1024];
    size_t len = sizeof(reply);
    int err;
    ULONG s, snum;
    INT ret;
    BOOL status;

    printf("WPA_CTRL: watchdog cb\n");

    ret = wifi_getSSIDNumberOfEntries(&snum);
    if (ret != RETURN_OK) {
        printf("%s: failed to get SSID count", __func__);
        return;
    }

    if (snum > MAX_APS) {
        printf("more ssid than supported! %lu\n", snum);
        return;
    }

    for (s = 0; s < snum; s++) {
        if (wifi_getApEnable(s, &status) != RETURN_OK) {
            printf("%s: failed to get AP Enable for index: %d\n", __func__, s);
            continue;
        }
        if (status == false) continue;

        memset(reply, 0, sizeof(reply));
        len = sizeof(reply);
        printf("WPA_CTRL: pinging index=%d\n", wpa_ctrl[s].ssid_index);
        err = ctrl_request(&wpa_ctrl[s], ping, strlen(ping), reply, &len);
        if (err == 0 && len > strlen(pong) && !strncmp(reply, pong, strlen(pong)))
            continue;

        printf("WPA_CTRL: ping timeout index=%d\n", wpa_ctrl[s].ssid_index);
        ctrl_close(&wpa_ctrl[s]);
        printf("WPA_CTRL: ev_timer_again %d\n", s);
        ev_timer_again(EV_DEFAULT_ &wpa_ctrl[s].retry);
    }
}

static int init_wpa()
{
    int ret = 0, i = 0;
    ULONG s, snum;

    ret = wifi_getSSIDNumberOfEntries(&snum);
    if (ret != RETURN_OK) {
        printf("%s: failed to get SSID count", __func__);
        return RETURN_ERR;
    }

    if (snum > MAX_APS) {
        printf("more ssid than supported! %lu\n", snum);
        return RETURN_ERR;
    }

    for (s = 0; s < snum; s++) {
        memset(&wpa_ctrl[s], 0, sizeof(struct ctrl));
        sprintf(wpa_ctrl[s].sockpath, "%s%lu", SOCK_PREFIX, s);
        wpa_ctrl[s].ssid_index = s;
        ctrl_enable(&wpa_ctrl[s]);
    }

    ev_timer_init(&wpa_ctrl->watchdog, ctrl_watchdog_cb, 0., 30.);
    ev_timer_again(EV_DEFAULT_ &wpa_ctrl->watchdog);

    initialized = 1;
    printf("WPA_CTRL: initialized\n");

    return RETURN_OK;
}

void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc)
{
    clients_connect_cb = callback_proc;
    if (!initialized)
        init_wpa();
}

void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc)
{
    clients_disconnect_cb = callback_proc;
    if (!initialized)
        init_wpa();
}

INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *outputMap, INT outputMapSize)
{
    int i;
    char cmd[256];
    char channel_numbers_buf[256];
    char dfs_state_buf[256];
    char line[256];
    const char *ptr;

    memset(cmd, 0, sizeof(cmd));
    memset(channel_numbers_buf, 0, sizeof(channel_numbers_buf));
    memset(line, 0, sizeof(line));
    memset(dfs_state_buf, 0, sizeof(dfs_state_buf));
    memset(outputMap, 0, outputMapSize); // all unused entries should be zero

    if (radioIndex == 0) { // 2.4G - all allowed
        if (outputMapSize < 11) {
            wifi_dbg_printf("%s: outputMapSize too small (%d)\n", __FUNCTION__, outputMapSize);
            return RETURN_ERR;
        }

        for (i = 0; i < 11; i++) {
            outputMap[i].ch_number = i + 1;
            outputMap[i].ch_state = CHAN_STATE_AVAILABLE;
        }

        return RETURN_OK;
    }

    if (radioIndex == 1) { // 5G
//  Example output of iw list:
//
//    		Frequencies:
//		* 5180 MHz [36] (17.0 dBm)
//		* 5200 MHz [40] (17.0 dBm)
//		* 5220 MHz [44] (17.0 dBm)
//		* 5240 MHz [48] (17.0 dBm)
//		* 5260 MHz [52] (23.0 dBm) (radar detection)
//		  DFS state: usable (for 78930 sec)
//		  DFS CAC time: 60000 ms
//		* 5280 MHz [56] (23.0 dBm) (radar detection)
//		  DFS state: usable (for 78930 sec)
//		  DFS CAC time: 60000 ms
//		* 5300 MHz [60] (23.0 dBm) (radar detection)
//		  DFS state: usable (for 78930 sec)
//		  DFS CAC time: 60000 ms
//		* 5320 MHz [64] (23.0 dBm) (radar detection)
//		  DFS state: usable (for 78930 sec)
//		  DFS CAC time: 60000 ms
//		* 5500 MHz [100] (disabled)
//		* 5520 MHz [104] (disabled)
//		* 5540 MHz [108] (disabled)
//		* 5560 MHz [112] (disabled)
//
//		Below command should fetch channel numbers of each enabled channel in 5GHz band:
        if (sprintf(cmd,"iw phy phy1 info | grep MHz | tr -d '\\t' | grep -v disabled | tr -d '*' | grep '^.* 5' | awk '{print $3}' | tr -d '[]'") < 0) {
            wifi_dbg_printf("%s: failed to build iw list command\n", __FUNCTION__);
            return RETURN_ERR;
        }

        if (_syscmd(cmd, channel_numbers_buf, sizeof(channel_numbers_buf)) == RETURN_ERR) {
            wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
            return RETURN_ERR;
        }

        ptr = channel_numbers_buf;
        i = 0;
        while (ptr = get_line_from_str_buf(ptr, line)) {
            if (i >= outputMapSize) {
                 wifi_dbg_printf("%s: DFS map size too small\n", __FUNCTION__);
                 return RETURN_ERR;
            }
            sscanf(line, "%d", &outputMap[i].ch_number);

            memset(cmd, 0, sizeof(cmd));
            // Below command should fetch string for DFS state (usable, available or unavailable)
            // Example line: "DFS state: usable (for 78930 sec)"
            if (sprintf(cmd,"iw phy phy1 info | grep -A 2 '\\[%d\\]' | tr -d '\\t' | grep 'DFS state' | awk '{print $3}' | tr -d '\\n'", outputMap[i].ch_number) < 0) {
                wifi_dbg_printf("%s: failed to build dfs state command\n", __FUNCTION__);
                return RETURN_ERR;
            }

            memset(dfs_state_buf, 0, sizeof(dfs_state_buf));
            if (_syscmd(cmd, dfs_state_buf, sizeof(dfs_state_buf)) == RETURN_ERR) {
                wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
                return RETURN_ERR;
            }

            wifi_dbg_printf("DFS state = '%s'\n", dfs_state_buf);

            if (!strcmp(dfs_state_buf, "usable")) {
                outputMap[i].ch_state = CHAN_STATE_DFS_NOP_FINISHED;
            } else if (!strcmp(dfs_state_buf, "available")) {
                outputMap[i].ch_state = CHAN_STATE_DFS_CAC_COMPLETED;
            } else if (!strcmp(dfs_state_buf, "unavailable")) {
                outputMap[i].ch_state = CHAN_STATE_DFS_NOP_START;
            } else {
                outputMap[i].ch_state = CHAN_STATE_AVAILABLE;
            }
            i++;
        }

        return RETURN_OK;
    }

    wifi_dbg_printf("%s: wrong radio index (%d)\n", __FUNCTION__, radioIndex);
    return RETURN_ERR;
}

INT wifi_chan_eventRegister(wifi_chan_eventCB_t eventCb)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_getRadioBandUtilization (INT radioIndex, INT *output_percentage)
{
    return RETURN_OK;
}

INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_switchBand(char *interface_name,INT radioIndex,char *freqBand)
{
    // TODO API refrence Implementaion is present on RPI hal
    return RETURN_ERR;
}

INT wifi_getRadioPercentageTransmitPower(INT apIndex, ULONG *txpwr_pcntg)
{
    //TO-Do Implement this
    txpwr_pcntg = 0;
    return RETURN_OK;
}

INT wifi_setZeroDFSState(UINT radioIndex, BOOL enable, BOOL precac)
{
     //Zero-wait DFS not supported
     return RETURN_ERR;
}

INT wifi_getZeroDFSState(UINT radioIndex, BOOL *enable, BOOL *precac)
{
     //Zero-wait DFS not supported
     return RETURN_ERR;
}

INT wifi_isZeroDFSSupported(UINT radioIndex, BOOL *supported)
{
     *supported = false;
     return RETURN_OK;
}

/* multi-psk support */
INT wifi_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key)
{
    char cmd[256];

    sprintf(cmd, "hostapd_cli -i %s%d sta %x:%x:%x:%x:%x:%x |grep '^keyid' | cut -f 2 -d = | tr -d '\n'",
        AP_PREFIX,
        apIndex,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    printf("DEBUG LOG wifi_getMultiPskClientKey(%s)\n",cmd);
    _syscmd(cmd, key->wifi_keyId, 64);


    return RETURN_OK;
}

INT wifi_pushMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
    FILE *fd      = NULL;
    char fname[100];
    char cmd[128] = {0};
    char out[64] = {0};
    wifi_key_multi_psk_t * key = NULL;
    if(keysNumber < 0)
            return RETURN_ERR;

    snprintf(fname, sizeof(fname), "/tmp/hostapd%d.psk", apIndex);
    fd = fopen(fname, "w");
    if (!fd) {
            return RETURN_ERR;
    }
    key= (wifi_key_multi_psk_t *) keys;
    for(int i=0; i<keysNumber; ++i, key++) {
        fprintf(fd, "keyid=%s 00:00:00:00:00:00 %s\n", key->wifi_keyId, key->wifi_psk);
    }
    fclose(fd);

    //reload file
    sprintf(cmd, "hostapd_cli -i%s%d raw RELOAD_WPA_PSK", AP_PREFIX, apIndex);
    _syscmd(cmd, out, 64);
    return RETURN_OK;
}

INT wifi_getMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
    FILE *fd      = NULL;
    char fname[100];
    char * line = NULL;
    char * pos = NULL;
    size_t len = 0;
    ssize_t read = 0;
    INT ret = RETURN_OK;
    wifi_key_multi_psk_t *keys_it = NULL;

    if (keysNumber < 1) {
        return RETURN_ERR;
    }

    snprintf(fname, sizeof(fname), "/tmp/hostapd%d.psk", apIndex);
    fd = fopen(fname, "r");
    if (!fd) {
        return RETURN_ERR;
    }

    if (keys == NULL) {
        ret = RETURN_ERR;
        goto close;
    }

    keys_it = keys;
    while ((read = getline(&line, &len, fd)) != -1) {
        //Strip trailing new line if present
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }

        if(strcmp(line,"keyid=")) {
            sscanf(line, "keyid=%s", &(keys_it->wifi_keyId));
            if (!(pos = index(line, ' '))) {
                ret = RETURN_ERR;
                goto close;
            }
            pos++;
            //Here should be 00:00:00:00:00:00
            if (!(strcmp(pos,"00:00:00:00:00:00"))) {
                 printf("Not supported MAC: %s\n", pos);
            }
            if (!(pos = index(pos, ' '))) {
                ret = RETURN_ERR;
                goto close;
            }
            pos++;

            //The rest is PSK
            snprintf(&keys_it->wifi_psk[0], sizeof(keys_it->wifi_psk), "%s", pos);
            keys_it++;

            if(--keysNumber <= 0)
		break;
        }
    }

close:
    free(line);
    fclose(fd);
    return ret;
}
/* end of multi-psk support */

INT wifi_setNeighborReports(UINT apIndex,
                             UINT numNeighborReports,
                             wifi_NeighborReport_t *neighborReports)
{
    char cmd[256] = { 0 };
    char hex_bssid[13] = { 0 };
    char bssid[18] = { 0 };
    char nr[256] = { 0 };
    char ssid[256];
    char hex_ssid[256];
    INT ret;

    /*rmeove all neighbors*/
    wifi_dbg_printf("\n[%s]: removing all neighbors from %s%d",__func__,AP_PREFIX,apIndex);
    sprintf(cmd, "hostapd_cli show_neighbor -i %s%d | awk '{print $1 \" \" $2}' | xargs -n2 -r hostapd_cli remove_neighbor -i %s%d",AP_PREFIX,apIndex,AP_PREFIX,apIndex);
    system(cmd);

    for(unsigned int i = 0; i < numNeighborReports; i++)
    {
        memset(ssid, 0, sizeof(ssid));
        ret = wifi_getSSIDName(apIndex, ssid);
        if (ret != RETURN_OK)
            return RETURN_ERR;

        memset(hex_ssid, 0, sizeof(hex_ssid));
        for(size_t j = 0,k = 0; ssid[j] != '\0' && k < sizeof(hex_ssid); j++,k+=2 )
            sprintf(hex_ssid + k,"%02x", ssid[j]);

        snprintf(hex_bssid, sizeof(hex_bssid),
                "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);
        snprintf(bssid, sizeof(bssid),
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);

        snprintf(nr, sizeof(nr),
                "%s"                                    // bssid
                "%02hhx%02hhx%02hhx%02hhx"              // bssid_info
                "%02hhx"                                // operclass
                "%02hhx"                                // channel
                "%02hhx",                               // phy_mode
                hex_bssid,
                neighborReports[i].info & 0xff, (neighborReports[i].info >> 8) & 0xff,
                (neighborReports[i].info >> 16) & 0xff, (neighborReports[i].info >> 24) & 0xff,
                neighborReports[i].opClass,
                neighborReports[i].channel,
                neighborReports[i].phyTable);

        snprintf(cmd, sizeof(cmd),
                "hostapd_cli set_neighbor "
                "%s "                        // bssid
                "ssid=%s "                   // ssid
                "nr=%s "                    // nr
                "-i %s%d",
                bssid,hex_ssid,nr,AP_PREFIX,apIndex);

        if (WEXITSTATUS(system(cmd)) != 0)
        {
            wifi_dbg_printf("\n[%s]: %s failed",__func__,cmd);
        }
    }

    return RETURN_OK;
}

INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_OK;
}

#ifdef _WIFI_HAL_TEST_
int main(int argc,char **argv)
{
    int index;
    INT ret=0;
    char buf[1024]="";

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(argc<3)
    {
        if(argc==2)
        {
            if(!strcmp(argv[1], "init"))
                return wifi_init();
            if(!strcmp(argv[1], "reset"))
                return wifi_reset();
            if(!strcmp(argv[1], "wifi_getHalVersion"))
            {
                char buffer[64];
                if(wifi_getHalVersion(buffer)==RETURN_OK)
                    printf("Version: %s\n", buffer);
                else
                    printf("Error in wifi_getHalVersion\n");
                return RETURN_OK;
            }
        }
        printf("wifihal <API> <radioIndex> <arg1> <arg2> ...\n");
        exit(-1);
    }

    index = atoi(argv[2]);
    if(strstr(argv[1], "wifi_getApName")!=NULL)
    {
        wifi_getApName(index,buf);
        printf("Ap name is %s \n",buf);
        return 0;
    }
    if(strstr(argv[1], "wifi_getRadioAutoChannelEnable")!=NULL)
    {
        BOOL b = FALSE;
        BOOL *output_bool = &b;
        wifi_getRadioAutoChannelEnable(index,output_bool);
        printf("Channel enabled = %d \n",b);
        return 0;
    }
    if(strstr(argv[1], "wifi_getApWpaEncryptionMode")!=NULL)
    {
        wifi_getApWpaEncryptionMode(index,buf);
        printf("encryption enabled = %s\n",buf);
        return 0;
    }
    if(strstr(argv[1], "wifi_getApSsidAdvertisementEnable")!=NULL)
    {
        BOOL b = FALSE;
        BOOL *output_bool = &b;
        wifi_getApSsidAdvertisementEnable(index,output_bool);
        printf("advertisment enabled =  %d\n",b);
        return 0;
    }
    if(strstr(argv[1],"wifi_getApAssociatedDeviceTidStatsResult")!=NULL)
    {
        if(argc <= 3 )
        {
            printf("Insufficient arguments \n");
            exit(-1);
        }

        char sta[20] = {'\0'};
        ULLONG handle= 0;
        strcpy(sta,argv[3]);
        mac_address_t st;
	mac_addr_aton(st,sta);

        wifi_associated_dev_tid_stats_t tid_stats;
        wifi_getApAssociatedDeviceTidStatsResult(index,&st,&tid_stats,&handle);
        for(int tid_index=0; tid_index<PS_MAX_TID; tid_index++) //print tid stats
            printf(" tid=%d \t ac=%d \t num_msdus=%lld \n" ,tid_stats.tid_array[tid_index].tid,tid_stats.tid_array[tid_index].ac,tid_stats.tid_array[tid_index].num_msdus);
    }

    if(strstr(argv[1], "getApEnable")!=NULL) {
        BOOL enable;
        ret=wifi_getApEnable(index, &enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "setApEnable")!=NULL) {
        BOOL enable = atoi(argv[3]);
        ret=wifi_setApEnable(index, enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "getApStatus")!=NULL) {
        char status[64]; 
        ret=wifi_getApStatus(index, status);
        printf("%s %d: %s, returns %d\n", argv[1], index, status, ret);
    }
    else if(strstr(argv[1], "wifi_getSSIDNameStatus")!=NULL)
    {
        wifi_getSSIDNameStatus(index,buf);
        printf("%s %d: active ssid : %s\n",argv[1], index,buf);
        return 0;
    }
    else if(strstr(argv[1], "getSSIDTrafficStats2")!=NULL) {
        wifi_ssidTrafficStats2_t stats={0};
        ret=wifi_getSSIDTrafficStats2(index, &stats); //Tr181
        printf("%s %d: returns %d\n", argv[1], index, ret);
        printf("     ssid_BytesSent             =%lu\n", stats.ssid_BytesSent);
        printf("     ssid_BytesReceived         =%lu\n", stats.ssid_BytesReceived);
        printf("     ssid_PacketsSent           =%lu\n", stats.ssid_PacketsSent);
        printf("     ssid_PacketsReceived       =%lu\n", stats.ssid_PacketsReceived);
        printf("     ssid_RetransCount          =%lu\n", stats.ssid_RetransCount);
        printf("     ssid_FailedRetransCount    =%lu\n", stats.ssid_FailedRetransCount);
        printf("     ssid_RetryCount            =%lu\n", stats.ssid_RetryCount);
        printf("     ssid_MultipleRetryCount    =%lu\n", stats.ssid_MultipleRetryCount);
        printf("     ssid_ACKFailureCount       =%lu\n", stats.ssid_ACKFailureCount);
        printf("     ssid_AggregatedPacketCount =%lu\n", stats.ssid_AggregatedPacketCount);
        printf("     ssid_ErrorsSent            =%lu\n", stats.ssid_ErrorsSent);
        printf("     ssid_ErrorsReceived        =%lu\n", stats.ssid_ErrorsReceived);
        printf("     ssid_UnicastPacketsSent    =%lu\n", stats.ssid_UnicastPacketsSent);
        printf("     ssid_UnicastPacketsReceived    =%lu\n", stats.ssid_UnicastPacketsReceived);
        printf("     ssid_DiscardedPacketsSent      =%lu\n", stats.ssid_DiscardedPacketsSent);
        printf("     ssid_DiscardedPacketsReceived  =%lu\n", stats.ssid_DiscardedPacketsReceived);
        printf("     ssid_MulticastPacketsSent      =%lu\n", stats.ssid_MulticastPacketsSent);
        printf("     ssid_MulticastPacketsReceived  =%lu\n", stats.ssid_MulticastPacketsReceived);
        printf("     ssid_BroadcastPacketsSent      =%lu\n", stats.ssid_BroadcastPacketsSent);
        printf("     ssid_BroadcastPacketsRecevied  =%lu\n", stats.ssid_BroadcastPacketsRecevied);
        printf("     ssid_UnknownPacketsReceived    =%lu\n", stats.ssid_UnknownPacketsReceived);
    }
    else if(strstr(argv[1], "getNeighboringWiFiDiagnosticResult2")!=NULL) {
        wifi_neighbor_ap2_t *neighbor_ap_array=NULL, *pt=NULL;
        UINT array_size=0;
        UINT i=0;
        ret=wifi_getNeighboringWiFiDiagnosticResult2(index, &neighbor_ap_array, &array_size);
        printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
        for(i=0, pt=neighbor_ap_array; i<array_size; i++, pt++) {	
            printf("  neighbor %d:\n", i);
            printf("     ap_SSID                =%s\n", pt->ap_SSID);
            printf("     ap_BSSID               =%s\n", pt->ap_BSSID);
            printf("     ap_Mode                =%s\n", pt->ap_Mode);
            printf("     ap_Channel             =%d\n", pt->ap_Channel);
            printf("     ap_SignalStrength      =%d\n", pt->ap_SignalStrength);
            printf("     ap_SecurityModeEnabled =%s\n", pt->ap_SecurityModeEnabled);
            printf("     ap_EncryptionMode      =%s\n", pt->ap_EncryptionMode);
            printf("     ap_SupportedStandards  =%s\n", pt->ap_SupportedStandards);
            printf("     ap_OperatingStandards  =%s\n", pt->ap_OperatingStandards);
            printf("     ap_OperatingChannelBandwidth   =%s\n", pt->ap_OperatingChannelBandwidth);
            printf("     ap_SecurityModeEnabled         =%s\n", pt->ap_SecurityModeEnabled);
            printf("     ap_BeaconPeriod                =%d\n", pt->ap_BeaconPeriod);
            printf("     ap_Noise                       =%d\n", pt->ap_Noise);
            printf("     ap_BasicDataTransferRates      =%s\n", pt->ap_BasicDataTransferRates);
            printf("     ap_SupportedDataTransferRates  =%s\n", pt->ap_SupportedDataTransferRates);
            printf("     ap_DTIMPeriod                  =%d\n", pt->ap_DTIMPeriod);
            printf("     ap_ChannelUtilization          =%d\n", pt->ap_ChannelUtilization);			
        }
        if(neighbor_ap_array)
            free(neighbor_ap_array); //make sure to free the list
    }
    else if(strstr(argv[1], "getApAssociatedDeviceDiagnosticResult")!=NULL) {
        wifi_associated_dev_t *associated_dev_array=NULL, *pt=NULL;
        UINT array_size=0;
        UINT i=0;
        ret=wifi_getApAssociatedDeviceDiagnosticResult(index, &associated_dev_array, &array_size);
        printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
        for(i=0, pt=associated_dev_array; i<array_size; i++, pt++) {	
            printf("  associated_dev %d:\n", i);
            printf("     cli_OperatingStandard      =%s\n", pt->cli_OperatingStandard);
            printf("     cli_OperatingChannelBandwidth  =%s\n", pt->cli_OperatingChannelBandwidth);
            printf("     cli_SNR                    =%d\n", pt->cli_SNR);
            printf("     cli_InterferenceSources    =%s\n", pt->cli_InterferenceSources);
            printf("     cli_DataFramesSentAck      =%lu\n", pt->cli_DataFramesSentAck);
            printf("     cli_DataFramesSentNoAck    =%lu\n", pt->cli_DataFramesSentNoAck);
            printf("     cli_BytesSent              =%lu\n", pt->cli_BytesSent);
            printf("     cli_BytesReceived          =%lu\n", pt->cli_BytesReceived);
            printf("     cli_RSSI                   =%d\n", pt->cli_RSSI);
            printf("     cli_MinRSSI                =%d\n", pt->cli_MinRSSI);
            printf("     cli_MaxRSSI                =%d\n", pt->cli_MaxRSSI);
            printf("     cli_Disassociations        =%d\n", pt->cli_Disassociations);
            printf("     cli_AuthenticationFailures =%d\n", pt->cli_AuthenticationFailures);
        }
        if(associated_dev_array)
            free(associated_dev_array); //make sure to free the list
    }

    if(strstr(argv[1],"wifi_getRadioChannelStats")!=NULL)
    {
#define MAX_ARRAY_SIZE 64
        int i, array_size;
        char *p, *ch_str;
        wifi_channelStats_t input_output_channelStats_array[MAX_ARRAY_SIZE];

        if(argc != 5)
        {
            printf("Insufficient arguments, Usage: wifihal wifi_getRadioChannelStats <AP-Index> <Array-Size> <Comma-seperated-channel-numbers>\n");
            exit(-1);
        }
        memset(input_output_channelStats_array, 0, sizeof(input_output_channelStats_array));

        for (i=0, array_size=atoi(argv[3]), ch_str=argv[4]; i<array_size; i++, ch_str=p)
        {
            strtok_r(ch_str, ",", &p);
            input_output_channelStats_array[i].ch_number = atoi(ch_str);
        }
        wifi_getRadioChannelStats(atoi(argv[2]), input_output_channelStats_array, array_size);
        if(!array_size)
            array_size=1;//Need to print current channel statistics
        for(i=0; i<array_size; i++)
            printf("chan num = %d \t, noise =%d\t ch_utilization_busy_rx = %lld \t,\
                    ch_utilization_busy_tx = %lld \t,ch_utilization_busy = %lld \t,\
                    ch_utilization_busy_ext = %lld \t, ch_utilization_total = %lld \t \n",\
                    input_output_channelStats_array[i].ch_number,\
                    input_output_channelStats_array[i].ch_noise,\
                    input_output_channelStats_array[i].ch_utilization_busy_rx,\
                    input_output_channelStats_array[i].ch_utilization_busy_tx,\
                    input_output_channelStats_array[i].ch_utilization_busy,\
                    input_output_channelStats_array[i].ch_utilization_busy_ext,\
                    input_output_channelStats_array[i].ch_utilization_total);
    }

    if(strstr(argv[1],"wifi_getAssociatedDeviceDetail")!=NULL)
    {
        if(argc <= 3 )
        {
            printf("Insufficient arguments \n");
            exit(-1);
        }
        char mac_addr[20] = {'\0'};
        wifi_device_t output_struct;
        int dev_index = atoi(argv[3]);

        wifi_getAssociatedDeviceDetail(index,dev_index,&output_struct);
        mac_addr_ntoa(mac_addr,output_struct.wifi_devMacAddress);
        printf("wifi_devMacAddress=%s \t wifi_devAssociatedDeviceAuthentiationState=%d \t, wifi_devSignalStrength=%d \t,wifi_devTxRate=%d \t, wifi_devRxRate =%d \t\n ", mac_addr,output_struct.wifi_devAssociatedDeviceAuthentiationState,output_struct.wifi_devSignalStrength,output_struct.wifi_devTxRate,output_struct.wifi_devRxRate);
    }

    if(strstr(argv[1],"wifi_setNeighborReports")!=NULL)
    {
        if (argc <= 3)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        char args[256];
        wifi_NeighborReport_t *neighborReports;

        neighborReports = calloc(argc - 2, sizeof(neighborReports));
        if (!neighborReports)
        {
            printf("Failed to allocate memory");
            exit(-1);
        }

        for (int i = 3; i < argc; ++i)
        {
            char *val;
            int j = 0;
            memset(args, 0, sizeof(args));
            strncpy(args, argv[i], sizeof(args));
            val = strtok(args, ";");
            while (val != NULL)
            {
                if (j == 0)
                {
                    mac_addr_aton(neighborReports[i - 3].bssid, val);
                } else if (j == 1)
                {
                    neighborReports[i - 3].info = strtol(val, NULL, 16);
                } else if (j == 2)
                {
                    neighborReports[i - 3].opClass = strtol(val, NULL, 16);
                } else if (j == 3)
                {
                    neighborReports[i - 3].channel = strtol(val, NULL, 16);
                } else if (j == 4)
                {
                    neighborReports[i - 3].phyTable = strtol(val, NULL, 16);
                } else {
                    printf("Insufficient arguments]n\n");
                    exit(-1);
                }
                val = strtok(NULL, ";");
                j++;
            }
        }

        INT ret = wifi_setNeighborReports(index, argc - 3, neighborReports);
        if (ret != RETURN_OK)
        {
            printf("wifi_setNeighborReports ret = %d", ret);
            exit(-1);
        }
    }
    if(strstr(argv[1],"wifi_getRadioIfName")!=NULL)
    {
        if((ret=wifi_getRadioIfName(index, buf))==RETURN_OK)
            printf("%s.\n", buf);
        else
            printf("Error returned\n");
    }
    if(strstr(argv[1],"wifi_getApSecurityModesSupported")!=NULL)
    {
        if((ret=wifi_getApSecurityModesSupported(index, buf))==RETURN_OK)
            printf("%s.\n", buf);
        else
            printf("Error returned\n");
    }
    if(strstr(argv[1],"wifi_getRadioOperatingChannelBandwidth")!=NULL)
    {
        if (argc <= 2)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        char buf[64]= {'\0'};
        wifi_getRadioOperatingChannelBandwidth(index,buf);
        printf("Current bandwidth is %s \n",buf);
        return 0;
    }
    if(strstr(argv[1],"pushRadioChannel2")!=NULL)
    {
        if (argc <= 5)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        UINT channel = atoi(argv[3]);
        UINT width = atoi(argv[4]);
        UINT beacon = atoi(argv[5]);
        INT ret = wifi_pushRadioChannel2(index,channel,width,beacon);
        printf("Result = %d", ret);
    }
    if (strstr(argv[1], "hostapdRead") != NULL)
    {
        char config_file[MAX_BUF_SIZE];
	int index_end;

        if (argc == 3)
        {
            index_end = index;
	}
	else if (argc == 4)
	{
            index_end = atoi(argv[3]);
	}
	else
	{
            printf("Incorrect arguments (argc=%d)\n", argc);
            exit(-1);
        }
	for ( ; index <= index_end; index += 1)
	{
            hapd_cfg_t cfg = {0};
            sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, index);
            if (0 == hapd_read_cfg(&cfg, config_file))
            {
	        sprintf(config_file, "%s%d-test.conf", CONFIG_PREFIX, index);
                hapd_write_cfg(&cfg, config_file);
                hapd_print_cfg(&cfg);
            }
        }
    }

    if (strstr(argv[1], "wifi_delApAclDevices") != NULL)
    {
         if(wifi_delApAclDevices(index) != RETURN_OK)
             printf("Error returned\n");
         return 0;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return 0;
}

#endif

#ifdef WIFI_HAL_VERSION_3

INT wifi_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    // The only par-radio parameter is a channel number, however there's a 'dynamic' API
    // to change it ("wifi_pushRadioChannel2()") that is used instead.
    return RETURN_OK;
}

INT wifi_getRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    INT ret;
    char band[128];
    ULONG channel;
    BOOL enabled;
    char buf[256];

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);

    ret = wifi_getRadioEnable(index, &enabled);
    if (ret != RETURN_OK)
    {
        printf("%s: cannot get enabled state for radio index %d\n", __func__,
                index);
        return RETURN_ERR;
    }
    operationParam->enable = enabled;

    memset(band, 0, sizeof(band));
    ret = wifi_getRadioOperatingFrequencyBand(index, band);
    if (ret != RETURN_OK)
    {
        printf("%s: cannot get radio band for radio index %d\n", __func__, index);
        return RETURN_ERR;
    }

    if (!strcmp(band, "2.4GHz"))
    {
        operationParam->band = WIFI_FREQUENCY_2_4_BAND;
        operationParam->variant = WIFI_80211_VARIANT_N;
    }
    else if (!strcmp(band, "5GHz"))
    {
        operationParam->band = WIFI_FREQUENCY_5_BAND;
        operationParam->variant = WIFI_80211_VARIANT_AC;
    }
    else
    {
        printf("%s: cannot decode band for radio index %d ('%s')\n", __func__, index,
            band);
    }

    memset(buf, 0, sizeof(buf));
    ret = wifi_getRadioOperatingChannelBandwidth(index, buf); // XXX: handle errors
    // XXX: only handle 20/40/80 modes for now
    if (!strcmp(buf, "20MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
    else if (!strcmp(buf, "40MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_40MHZ;
    else if (!strcmp(buf, "80MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
    else
    {
        printf("%s: Unknown HT mode: '%s'\n", __func__, buf);
        operationParam->channelWidth = 0;
    }

    ret = wifi_getRadioChannel(index, &channel);
    if (ret != RETURN_OK)
    {
        printf("%s: Failed to get channel number for radio index %d\n", __func__, index);
        channel = 0;
    }
    operationParam->channel = channel;
    operationParam->csa_beacon_count = 15; // XXX: hardcoded for now

    operationParam->countryCode = wifi_countrycode_US; // XXX: hardcoded for now

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

static int array_index_to_vap_index(UINT radioIndex, int arrayIndex)
{
    if (radioIndex != 0 && radioIndex != 1)
    {
        printf("%s: Wrong radio index (%d)\n", __func__, index);
        return -1;
    }

    // XXX: hardcode vap indexes for now (0,1 - home, 2,3 - backhaul 6,7 - onboard)
    // XXX : assumed radioIndex for 2.4 is 0 radioIndex for 5G is 1

    return (arrayIndex * 2) + radioIndex;
}

INT wifi_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    INT ret;
    int i;
    BOOL enabled = false;
    char buf[256];
    wifi_secur_list *secur_item;
    int vap_index;
    INT mode;
    map->num_vaps = 5; // XXX: this is a hack. For both radio let's support 5 vaps for now
    ULONG lval;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);

    map->vap_array[index].radio_index = index;
    for (i = 0; i < 5; i++)
    {
        vap_index = array_index_to_vap_index(index, i);
        if (vap_index < 0)
	{
            return RETURN_ERR;
        }

        strncpy(map->vap_array[i].bridge_name, "brlan0", sizeof(map->vap_array[i].bridge_name) - 1);

        map->vap_array[i].vap_index = vap_index;
        map->vap_array[i].vap_mode = wifi_vap_mode_ap;

        memset(buf, 0, sizeof(buf));
        wifi_getApName(vap_index, buf); // XXX: error handling
        strncpy(map->vap_array[i].vap_name, buf, sizeof(map->vap_array[i].vap_name) - 1);

        ret = wifi_getSSIDEnable(vap_index, &enabled);
        if (ret != RETURN_OK)
        {
            printf("%s: failed to get SSIDEnable for index %d\n", __func__, i);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.enabled = enabled;

        memset(buf, 0, sizeof(buf));
        wifi_getBaseBSSID(vap_index, buf);
        sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &map->vap_array[i].u.bss_info.bssid[0],
            &map->vap_array[i].u.bss_info.bssid[1],
            &map->vap_array[i].u.bss_info.bssid[2],
            &map->vap_array[i].u.bss_info.bssid[3],
            &map->vap_array[i].u.bss_info.bssid[4],
            &map->vap_array[i].u.bss_info.bssid[5]); // XXX: handle error

        wifi_getApSsidAdvertisementEnable(vap_index, &enabled); // XXX: error handling
        map->vap_array[i].u.bss_info.showSsid = enabled;

        wifi_getApMacAddressControlMode(vap_index, &mode); // XXX: handle errors
        if (mode == 0) map->vap_array[i].u.bss_info.mac_filter_enable = false;
        else map->vap_array[i].u.bss_info.mac_filter_enable = true;

        if (mode == 1) map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        else if (mode == 2) map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list; // XXX: handle wrong mode

        memset(buf, 0, sizeof(buf));
        wifi_getSSIDNameStatus(vap_index, buf); // XXX: error handling
        strncpy(map->vap_array[i].u.bss_info.ssid, buf, sizeof(map->vap_array[i].u.bss_info.ssid) - 1);

        wifi_getApSecurityModeEnabled(vap_index, buf);

        if (!(secur_item = wifi_get_item_by_str(ARRAY_AND_SIZE(map_security), buf)))
        {
            printf("%s: ssid_index %d: Failed to decode security mode (%s)\n", __func__, vap_index, buf);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.security.mode = secur_item->key;

        memset(buf, 0, sizeof(buf));
        wifi_getApSecurityKeyPassphrase(vap_index, buf); // XXX: error handling
        strncpy(map->vap_array[i].u.bss_info.security.u.key.key, buf, sizeof(map->vap_array[i].u.bss_info.security.u.key.key) - 1);

        wifi_getNeighborReportActivation(vap_index, &enabled); // XXX: error handling
        map->vap_array[i].u.bss_info.nbrReportActivated = enabled;

        wifi_getBSSTransitionActivation(vap_index, &enabled); // XXX: error handling
        map->vap_array[i].u.bss_info.bssTransitionActivated = enabled;

        wifi_getApIsolationEnable(vap_index, &enabled);
        map->vap_array[i].u.bss_info.isolation = enabled;

       /* mcast2ucast - TBD */
       map->vap_array[i].u.bss_info.mcast2ucast = false;
    }
#if defined(_TURRIS_EXTENDER_) || defined(_RPI_EXTENDER_)
    // vap indexes for bhaul-sta
    map->num_vaps = 6;

    if (index == 0) vap_index = 10;
    else if (index == 1) vap_index = 11;

    memset(buf, 0, sizeof(buf));
    ret = wifi_getSTAName(vap_index, buf);
    if (ret != RETURN_OK || strlen(buf) == 0)
    {
        printf("%s: cannot get sta name for index %d\n", __func__, vap_index);
    }
    else strncpy(map->vap_array[5].vap_name, buf, sizeof(map->vap_array[5].vap_name) - 1);

    map->vap_array[5].vap_index = vap_index;
    map->vap_array[5].vap_mode = wifi_vap_mode_sta;

    ret = wifi_getSTAEnabled(vap_index, &enabled);
    if (ret != RETURN_OK)
    {
        printf("%s: failed to get STAEnabled for index %d\n", __func__, vap_index);
    }
    else map->vap_array[5].u.sta_info.enabled = enabled;

    memset(buf, 0, sizeof(buf));
    ret = wifi_getSTASSID(vap_index, buf);
    if (ret != RETURN_OK || strlen(buf) == 0)
    {
        printf("%s: failed to get STA SSID for index %d\n", __func__, vap_index);
    }
    else strncpy(map->vap_array[5].u.sta_info.ssid, buf, sizeof(map->vap_array[5].u.sta_info.ssid) - 1);

    memset(buf, 0, sizeof(buf));
    ret = wifi_getSTABSSID(vap_index, buf);
    if (ret != RETURN_OK || strlen(buf) == 0)
    {
        printf("%s: failed to get STA BSSID for index %d\n", __func__, vap_index);
    }
    else
    {
        sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &map->vap_array[i].u.sta_info.bssid[0],
            &map->vap_array[i].u.sta_info.bssid[1],
            &map->vap_array[i].u.sta_info.bssid[2],
            &map->vap_array[i].u.sta_info.bssid[3],
            &map->vap_array[i].u.sta_info.bssid[4],
            &map->vap_array[i].u.sta_info.bssid[5]); // XXX: handle error
    }

    memset(buf, 0, sizeof(buf));
    ret = wifi_getSTAMAC(vap_index, buf);
    if (ret != RETURN_OK || strlen(buf) == 0)
    {
        printf("%s: failed to get STA MAC for index %d\n", __func__, vap_index);
    }
    else
    {
        sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &map->vap_array[i].u.sta_info.mac[0],
            &map->vap_array[i].u.sta_info.mac[1],
            &map->vap_array[i].u.sta_info.mac[2],
            &map->vap_array[i].u.sta_info.mac[3],
            &map->vap_array[i].u.sta_info.mac[4],
            &map->vap_array[i].u.sta_info.mac[5]); // XXX: handle error
    }

    ret = wifi_getRadioChannel(index, &lval);
    if (ret != RETURN_OK)
    {
        printf("%s: Failed to get channel from radio idx %d for index %d\n", __func__, index, vap_index);
    }
    else map->vap_array[5].u.sta_info.scan_params.channel.channel = lval;

    if (strlen(map->vap_array[5].u.sta_info.ssid))
    {
        BOOL out_scan_cur_freq;
        int out_array_size = 30;
        wifi_sta_network_t * out_staNetworks_array = (wifi_sta_network_t *) calloc(out_array_size, sizeof(wifi_sta_network_t));
        ret = wifi_getSTANetworks(vap_index, &out_staNetworks_array, out_array_size, &out_scan_cur_freq);
        if (ret != RETURN_OK)
        {
            printf("%s: Failed to get STA (credentials) for index %d\n", __func__, vap_index);
        }
        else
        {
            wifi_sta_network_t * staNetwork = out_staNetworks_array;
            map->vap_array[5].u.sta_info.security.u.key.type = wifi_security_key_type_psk;
            strncpy(map->vap_array[5].u.sta_info.security.u.key.key, staNetwork->psk, sizeof(map->vap_array[5].u.sta_info.security.u.key.key) - 1); 

            if (!strcmp(staNetwork->proto, "WPA RSN"))
            {
                map->vap_array[5].u.sta_info.security.mode = wifi_security_mode_wpa_wpa2_personal;
            }
            else if (!strcmp(staNetwork->proto, "RSN"))
            {
                map->vap_array[5].u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
            }
            else if (!strcmp(staNetwork->proto, "WPA"))
            {
                map->vap_array[5].u.sta_info.security.mode = wifi_security_mode_wpa_personal;
            }
            map->vap_array[5].u.sta_info.security.encr = wifi_encryption_tkip;
        }
    }
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    unsigned int i, j;
    wifi_vap_info_t *vap_info = NULL;
    int acl_mode;
    char *sec_str = NULL;
    wifi_sta_network_t * sta = (wifi_sta_network_t *) calloc(1,sizeof(wifi_sta_network_t));

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);
    for (i = 0; i < map->num_vaps; i++)
    {
        vap_info = &map->vap_array[i];
        printf("Create VAP for ssid_index=%d (vap_num=%d)\n", vap_info->vap_index, i);

        if (vap_info->vap_mode == wifi_vap_mode_ap)
        {
            if (vap_info->u.bss_info.mac_filter_enable == false) acl_mode = 0;
            else
            {
                if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) acl_mode = 0;
                else acl_mode = 1;
            }
            wifi_setApMacAddressControlMode(vap_info->vap_index, acl_mode); // XXX: handle errors
            wifi_setApSsidAdvertisementEnable(vap_info->vap_index, vap_info->u.bss_info.showSsid); // XXX: handle errors
            wifi_setSSIDName(vap_info->vap_index, vap_info->u.bss_info.ssid); // XXX: handle errors

            sec_str = wifi_get_str_by_key(ARRAY_AND_SIZE(map_security), vap_info->u.bss_info.security.mode);
            if (sec_str)
            {
                wifi_setApSecurityModeEnabled(vap_info->vap_index, sec_str); // XXX: handle errors
            }
            else
            {
                printf("Cannot map security mode: %d\n", (int)vap_info->u.bss_info.security.mode);
            }

            wifi_setApSecurityKeyPassphrase(vap_info->vap_index, vap_info->u.bss_info.security.u.key.key); // XXX: handle errors, handle radius
            wifi_setApIsolationEnable(vap_info->vap_index, vap_info->u.bss_info.isolation);

            wifi_setNeighborReportActivation(vap_info->vap_index, vap_info->u.bss_info.nbrReportActivated); // XXX: handle errors
            wifi_setBSSTransitionActivation(vap_info->vap_index, vap_info->u.bss_info.bssTransitionActivated); // XXX: handle errors

            printf("Calling wifi_applySSIDSettings for index: %d\n", vap_info->vap_index);

            wifi_setSSIDEnable(vap_info->vap_index, vap_info->u.bss_info.enabled); // XXX: handle errors
            wifi_applySSIDSettings(vap_info->vap_index); // XXX: handle errors, don't call if no changes.
        }
#if defined(_TURRIS_EXTENDER_) || defined(_RPI_EXTENDER_)
        else if (vap_info->vap_mode == wifi_vap_mode_sta)
        {
            wifi_setSTAEnabled(vap_info->vap_index, vap_info->u.sta_info.enabled);

            sprintf(sta->ssid, vap_info->u.sta_info.ssid);
            for (j=0; j<sizeof(sta->bssid); j++) sta->bssid[j] = vap_info->u.sta_info.bssid[j];

            if (vap_info->u.sta_info.security.mode == wifi_security_mode_wpa_wpa2_personal)
            {
                sprintf(sta->pairwise, "CCMP TKIP");
                sprintf(sta->proto, "WPA RSN");
            }
            else if (vap_info->u.sta_info.security.mode == wifi_security_mode_wpa2_personal)
            {
                sprintf(sta->pairwise, "CCMP");
                sprintf(sta->proto, "RSN");
            }
            else if (vap_info->u.sta_info.security.mode == wifi_security_mode_wpa_personal)
            {
                sprintf(sta->pairwise, "TKIP");
                sprintf(sta->proto, "WPA");
            }
            else
            {
                sprintf(sta->pairwise, "CCMP");
                sprintf(sta->proto, "RSN");
            }
            if (vap_info->u.sta_info.security.u.key.type == wifi_security_key_type_psk) sprintf(sta->key_mgmt, "WPA-PSK");
            sprintf(sta->psk, vap_info->u.sta_info.security.u.key.key);
            wifi_setSTANetworks(vap_info->vap_index, &sta, 1, false);
        }
#endif
    }
    free(sta);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

int parse_channel_list_int_arr(char *pchannels, wifi_channels_list_t* chlistptr)
{
    char *token, *next;
    const char s[2] = ",";
    int count =0;

    /* get the first token */
    token = strtok_r(pchannels, s, &next);

    /* walk through other tokens */
    while( token != NULL && count < MAX_CHANNELS) {
        chlistptr->channels_list[count++] = atoi(token);
        token = strtok_r(NULL, s, &next);
    }

    return count;
}

static int getRadioCapabilities(int radioIndex, wifi_radio_capabilities_t *rcap)
{
    INT status;
    wifi_channels_list_t *chlistp;
    CHAR output_string[64];
    CHAR pchannels[128];

    if(rcap == NULL)
    {
        return RETURN_ERR;
    }

    rcap->index = radioIndex;
    rcap->numSupportedFreqBand = 1;
    if (1 == radioIndex)
      rcap->band[0] = WIFI_FREQUENCY_5_BAND;
    else
      rcap->band[0] = WIFI_FREQUENCY_2_4_BAND;


    chlistp = &(rcap->channel_list[0]);
    memset(pchannels, 0, sizeof(pchannels));

    /* possible number of radio channels */
    status = wifi_getRadioPossibleChannels(radioIndex, pchannels);
    if (status != RETURN_OK)
    {
         printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, pchannels);
    }
    /* Number of channels and list*/
    chlistp->num_channels = parse_channel_list_int_arr(pchannels, chlistp);

    /* autoChannelSupported */
    /* always ON with wifi_getRadioAutoChannelSupported */
    rcap->autoChannelSupported = TRUE;

    /* DCSSupported */
    /* always ON with wifi_getRadioDCSSupported */
    rcap->DCSSupported = TRUE;

    /* zeroDFSSupported - TBD */
    rcap->zeroDFSSupported = FALSE;

    /* mcast2ucastSupported - TBD */
    rcap->mcast2ucastSupported = FALSE;

    /* Supported Country List*/
    memset(output_string, 0, sizeof(output_string));
    status = wifi_getRadioCountryCode(radioIndex, output_string);
    if (status != RETURN_OK)
    {
        printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, output_string);
        return RETURN_ERR;
    }

    if(!strcmp(output_string,"US")){
        rcap->countrySupported[0] = wifi_countrycode_US;
        rcap->countrySupported[1] = wifi_countrycode_CA;
    } else if (!strcmp(output_string,"CA")) {
        rcap->countrySupported[0] = wifi_countrycode_CA;
        rcap->countrySupported[1] = wifi_countrycode_US;
    } else {
        printf("[wifi_hal dbg] : func[%s] line[%d] radio_index[%d] Invalid Country [%s]\n", __FUNCTION__, __LINE__, radioIndex, output_string);
    }

    rcap->numcountrySupported = 2;

    /* csi */
    rcap->csi.maxDevices = 8;
    rcap->csi.soudingFrameSupported = TRUE;

    snprintf(rcap->ifaceName, 64, "wlan%d", radioIndex);

    /* channelWidth - all supported bandwidths */
    int i=0;
    rcap->channelWidth[i] = 0;
    if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
        rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
                                WIFI_CHANNELBANDWIDTH_40MHZ);

    }
    else if (rcap->band[i] & (WIFI_FREQUENCY_5_BAND )) {
        rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
                                WIFI_CHANNELBANDWIDTH_40MHZ |
                                WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ);
    }


    /* mode - all supported variants */
    // rcap->mode[i] = WIFI_80211_VARIANT_H;
    if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND ) {
        rcap->mode[i] = (WIFI_80211_VARIANT_N);
    }
    else if (rcap->band[i] & WIFI_FREQUENCY_5_BAND ) {
        rcap->mode[i] = ( WIFI_80211_VARIANT_AC );
    }
    rcap->maxBitRate[i] = ( rcap->band[i] & WIFI_FREQUENCY_2_4_BAND ) ? 300 :
        ((rcap->band[i] & WIFI_FREQUENCY_5_BAND) ? 1734 : 0);

    /* supportedBitRate - all supported bitrates */
    rcap->supportedBitRate[i] = 0;
    if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
        rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
                                    WIFI_BITRATE_11MBPS | WIFI_BITRATE_12MBPS);
    }
    else if (rcap->band[i] & (WIFI_FREQUENCY_5_BAND )) {
        rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
                                    WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS |
                                    WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS);
    }


    rcap->transmitPowerSupported_list[i].numberOfElements = 5;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[0]=12;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[1]=25;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[2]=50;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[3]=75;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[4]=100;
    rcap->cipherSupported = 0;
    rcap->cipherSupported |= WIFI_CIPHER_CAPA_ENC_TKIP | WIFI_CIPHER_CAPA_ENC_CCMP;
    rcap->maxNumberVAPs = MAX_NUM_VAP_PER_RADIO;

    return RETURN_OK;
}

INT wifi_getHalCapability(wifi_hal_capability_t *cap)
{
    INT status, radioIndex;
    char cmd[MAX_BUF_SIZE], output[MAX_BUF_SIZE];
    int iter = 0;
    unsigned int j;
    wifi_interface_name_idex_map_t *iface_info;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    memset(cap, 0, sizeof(wifi_hal_capability_t));

    /* version */
    cap->version.major = WIFI_HAL_MAJOR_VERSION;
    cap->version.minor = WIFI_HAL_MINOR_VERSION;

    /* number of radios platform property */
    snprintf(cmd, sizeof(cmd), "ls -d /sys/class/net/wlan* | wc -l");
    _syscmd(cmd, output, sizeof(output));
    cap->wifi_prop.numRadios = atoi(output);

    for(radioIndex=0; radioIndex < cap->wifi_prop.numRadios; radioIndex++)
    {
        status = getRadioCapabilities(radioIndex, &(cap->wifi_prop.radiocap[radioIndex]));
        if (status != 0) {
            printf("%s: getRadioCapabilities idx = %d\n", __FUNCTION__, radioIndex);
            return RETURN_ERR;
        }

        for (j = 0; j < cap->wifi_prop.radiocap[radioIndex].maxNumberVAPs; j++)
        {
            if (iter >= MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)
            {
                 printf("%s: to many vaps for index map (%d)\n", __func__, iter);
                 return RETURN_ERR;
            }
            iface_info = &cap->wifi_prop.interface_map[iter];
            iface_info->phy_index = radioIndex; // XXX: parse phyX index instead
            iface_info->rdk_radio_index = radioIndex;
            memset(output, 0, sizeof(output));
            if (wifi_getRadioIfName(radioIndex, output) == RETURN_OK)
            {
                strncpy(iface_info->interface_name, output, sizeof(iface_info->interface_name) - 1);
            }
            // TODO: bridge name
            // TODO: vlan id
            // TODO: primary
            iface_info->index = array_index_to_vap_index(radioIndex, j);
            memset(output, 0, sizeof(output));
            if (iface_info >= 0 && (iface_info->index < 10 && wifi_getApName(iface_info->index, output) == RETURN_OK)
#if defined(_TURRIS_EXTENDER_) || defined(_RPI_EXTENDER_)
                                || (wifi_getSTAName(iface_info->index, output) == RETURN_OK)
#endif
            )
            {
                 strncpy(iface_info->vap_name, output, sizeof(iface_info->vap_name) - 1);
            }
            iter++;

        }
    }

    cap->BandSteeringSupported = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setApSecurity(INT ap_index, wifi_vap_security_t *security)
{
    //TODO
    return RETURN_OK;
}

INT wifi_getApSecurity(INT ap_index, wifi_vap_security_t *security)
{
    //TODO
    return RETURN_OK;
}

#endif /* WIFI_HAL_VERSION_3 */

#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_getApAssociatedDevice(INT ap_index, mac_address_t *output_deviceMacAddressArray, UINT maxNumDevices, UINT *output_numDevices)
{
     return RETURN_OK;
}
#else
INT wifi_getApAssociatedDevice(INT ap_index, CHAR *output_buf, INT output_buf_size)
{
    char cmd[128];
    BOOL status = false;

    if(ap_index > MAX_APS || output_buf == NULL || output_buf_size <= 0)
        return RETURN_ERR;

    output_buf[0] = '\0';

    wifi_getApEnable(ap_index,&status);
    if (!status)
        return RETURN_OK;

    sprintf(cmd, "hostapd_cli -i %s%d list_sta | tr '\\n' ',' | sed 's/.$//'", AP_PREFIX, ap_index);
    _syscmd(cmd, output_buf, output_buf_size);
    
    return RETURN_OK;
}
#endif
