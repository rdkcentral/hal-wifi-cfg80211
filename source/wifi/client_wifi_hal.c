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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include "wifi_hal.h"
#include "client_wifi_hal.h"

#include <ev.h>
#include <wpa_ctrl.h>
#include <errno.h>
#include <net/if.h>
#define SOCK_PREFIX "/var/run/wpa_supplicant/"

#if defined(_TURRIS_EXTENDER_) || defined(_RPI_EXTENDER_)

/* Helper wpa_supplicant events */
#ifndef container_of
#define offsetof(st, m) ((size_t)&(((st *)0)->m))
#define container_of(ptr, type, member) \
                   ((type *)((char *)ptr - offsetof(type, member)))
#endif /* container_of */
static int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0, cmd_ret=0;

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

    return cmd_ret >> 8;
}

struct ctrl {
    char sockpath[128];
    char sockdir[128];
    char bss[IFNAMSIZ];
    int ssid_index;
    void (*cb)(struct ctrl *ctrl, int level, const char *buf, size_t len);
    void (*overrun)(struct ctrl *ctrl);
    void (*closed)(struct ctrl *ctrl);
    struct wpa_ctrl *wpa;
    unsigned int ovfl;
    int initialized;
    ev_timer retry;
    ev_stat stat;
    ev_io io;
    char reply[4096];
    size_t reply_len;
    ev_timer watchdog;
};
static wifi_client_event_callback clients_connect_cb;
static struct ctrl wpa_ctrl[2];
static int client_initialized;

static void ctrl_close(struct ctrl *ctrl)
{
    if (ctrl->io.cb)
        ev_io_stop(EV_DEFAULT_ &ctrl->io);
    if (ctrl->retry.cb)
        ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
    if (ctrl->watchdog.cb)
        ev_timer_stop(EV_DEFAULT_ &ctrl->watchdog);
    if (!ctrl->wpa)
        return;

    wpa_ctrl_detach(ctrl->wpa);
    wpa_ctrl_close(ctrl->wpa);
    ctrl->wpa = NULL;
    
    if (ctrl->closed)
        ctrl->closed(ctrl);
}

static void ctrl_process(struct ctrl *ctrl)
{
    char *str;
    size_t len;
    char buf[1024];
    int drops;
    int level;
    int err;
    char * k;
    char * v;
    char *kv;
    wifi_client_associated_dev_t ap;
    memset(&ap, 0, sizeof(ap));

    /* Example events:
     *
     * CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
     * CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
    */
    if (!(str = index(ctrl->reply, '>')))
        return;
    if (sscanf(ctrl->reply, "<%d>", &level) != 1)
        return;

    str++;
 
    if (strncmp("CTRL-EVENT-CONNECTED ", str, 21) == 0) {
        strsep(&str, " "); /* "-" */
        strsep(&str, " "); /* "Connection" */
        strsep(&str, " "); /* "to" */

        sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &ap.MACAddress[0], &ap.MACAddress[1], &ap.MACAddress[2],
                &ap.MACAddress[3], &ap.MACAddress[4], &ap.MACAddress[5]);
        strsep(&str, " [id="); // completed
        ap.NetworkID = atoi(str);
       
        ap.connected = true;       
       
        (clients_connect_cb)(ctrl->ssid_index, &ap);
        goto handled;
    }
    if (strncmp("CTRL-EVENT-DISCONNECTED ", str, 24) == 0) {
        while ((kv = strsep(&str, " "))) {
            if ((k = strsep(&kv, "=")) &&
                (v = strsep(&kv, ""))) {
                if (!strcmp(k, "bssid"))
                    sscanf(v, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &ap.MACAddress[0], &ap.MACAddress[1], &ap.MACAddress[2],
                        &ap.MACAddress[3], &ap.MACAddress[4], &ap.MACAddress[5]);

                else if (!strcmp(k, "reason"))
                    ap.reason = atoi(v);
                else if (!strcmp(k, "locally_generated"))
                    ap.locally_generated = atoi(v);
            }
        }
        ap.connected = false;
        (clients_connect_cb)(ctrl->ssid_index, &ap);
        goto handled;
    }

handled:

    return;

}

static void ctrl_ev_cb(EV_P_ struct ev_io *io, int events) {
    struct ctrl *ctrl = container_of(io, struct ctrl, io);
    int err;

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
    ev_io_init(&ctrl->io, ctrl_ev_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &ctrl->io);

    ev_timer_again(EV_DEFAULT_ &ctrl->watchdog);

    return 0;

err_detach:
    wpa_ctrl_detach(ctrl->wpa);
err_close:
    wpa_ctrl_close(ctrl->wpa);
err:
    ctrl->wpa = NULL;
    return -1;
}

static void ctrl_msg_cb(char *buf, size_t len)
{
    struct ctrl *ctrl = container_of(buf, struct ctrl, reply);
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
    if (err < 0)
        return err;

    if (ctrl->reply_len > *reply_len)
        ctrl->reply_len = *reply_len;

    *reply_len = ctrl->reply_len;
    memcpy(reply, ctrl->reply, *reply_len);
    reply[*reply_len] = 0;
    return 0;
}

static void
ctrl_watchdog_cb(EV_P_ ev_timer *timer, int events)
{
    struct ctrl *ctrl = container_of(timer, struct ctrl, watchdog);
    const char *pong = "PONG";
    const char *ping = "PING";
    char reply[1024];
    size_t len = sizeof(reply);
    int err;
    err = ctrl_request(ctrl, ping, strlen(ping), reply, &len);
    if (err == 0 && len > strlen(pong) && !strncmp(reply, pong, strlen(pong))) {
        return;
    }
    ctrl_close(ctrl);
    ev_timer_again(EV_A_ &ctrl->retry);
}


static void ctrl_stat_cb(EV_P_ ev_stat *stat, int events)
{
    struct ctrl *ctrl = container_of(stat, struct ctrl, stat);

    printf("%s: file state changed", ctrl->bss);
    ctrl_open(ctrl);
}

static void ctrl_retry_cb(EV_P_ ev_timer *timer, int events)
{
    struct ctrl *ctrl = container_of(timer, struct ctrl, retry);

    printf("CTRL %s: retrying", ctrl->bss);
    if (ctrl_open(ctrl) < 0)
        ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

static int ctrl_enable(struct ctrl *ctrl)
{
    if (ctrl->wpa)
        return 0;

    if (!ctrl->stat.cb) {
        ev_stat_init(&ctrl->stat, ctrl_stat_cb, ctrl->sockpath, 0.);
        ev_stat_start(EV_DEFAULT_ &ctrl->stat);
    }

    if (!ctrl->retry.cb)
        ev_timer_init(&ctrl->retry, ctrl_retry_cb, 0., 5.);

    if (!ctrl->watchdog.cb)
        ev_timer_init(&ctrl->watchdog, ctrl_watchdog_cb, 0., 30.);


    return ctrl_open(ctrl);
}

/* client API */
INT wifi_getSTANumberOfEntries(ULONG *output) //Tr181
{
    if (NULL == output)
        return RETURN_ERR;

    *output = 2;
    return RETURN_OK;
}

INT wifi_getSTAName(INT apIndex, CHAR *output_string)
{
    if (NULL == output_string)
        return RETURN_ERR;
    if (apIndex == 10)
        snprintf(output_string, 16, "bhaul-sta-24");
    else if (apIndex == 11)
        snprintf(output_string, 16, "bhaul-sta-50");

    return RETURN_OK;
}

INT wifi_getSTARadioIndex(INT ssidIndex, INT *radioIndex)
{
    if (NULL == radioIndex)
        return RETURN_ERR;
    *radioIndex = ssidIndex%2;
    return RETURN_OK;
}

INT wifi_getSTAMAC(INT ssidIndex, CHAR *output_string)
{
    char cmd[128] = {0};
    int ret = 0;
    char ssid_ifname[128];

    if (NULL == output_string)
        return RETURN_ERR;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {   
        return RETURN_ERR;
    }

    sprintf(cmd, "wpa_cli -i%s status |grep '^address' | cut -f 2 -d =", ssid_ifname);
    _syscmd(cmd, output_string, 64);

    return RETURN_OK;
}

INT wifi_getSTABSSID(INT ssidIndex, CHAR *output_string)
{
    char cmd[128] = {0};
    int ret = 0;
    char ssid_ifname[128];

    if (NULL == output_string)
        return RETURN_ERR;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {
        return RETURN_ERR;
    }

    sprintf(cmd, "wpa_cli -i%s status |grep bssid | cut -f 2 -d =", ssid_ifname);
    _syscmd(cmd, output_string, 64);

    return RETURN_OK;
}

INT wifi_getSTASSID(INT ssidIndex, CHAR *output_string)
{
    char cmd[128] = {0};
    int ret = 0;
    char ssid_ifname[128];

    if (NULL == output_string)
        return RETURN_ERR;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {
        return RETURN_ERR;
    }

    sprintf(cmd, "wpa_cli -i%s status |grep ^ssid | cut -f 2 -d = | tr -d '\n'", ssid_ifname);
    _syscmd(cmd, output_string, 64);

    return RETURN_OK;
}

INT wifi_getSTACredentials(INT ssidIndex, CHAR *output_string)
{
    char cmd[128] = {0};
    int ret = 0;
    char ssid_ifname[128];

    if (NULL == output_string)
        return RETURN_ERR;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {   
        return RETURN_ERR;
    }

    sprintf(cmd, "wpa_cli -i%s status |grep ssid | cut -f 2 -d =", ssid_ifname);
    _syscmd(cmd, output_string, 64);

    return RETURN_OK;
}

static int init_client_wpa()
{
    int ret = 0, i = 0;
    ULONG s, snum;
    char * sock_path;
    char ssid_ifname[128];

    ret = wifi_getSTANumberOfEntries(&snum);
    if (ret != RETURN_OK) {
        printf("%s: failed to get SSID count", __func__);
        return RETURN_ERR;
    }

    for (s = 0; s < snum; s++) {
        ret = wifi_getSTAName(s+10, ssid_ifname);
        if (ret != RETURN_OK)
        {   
            return RETURN_ERR;
        }
        sprintf(wpa_ctrl[s].sockpath, "%s%s", SOCK_PREFIX, ssid_ifname);
        wpa_ctrl[s].ssid_index = s+10;
        printf("Opening ctrl for %s\n", ssid_ifname);
        if (ctrl_enable(&wpa_ctrl[s]))
        {
             return RETURN_ERR;
        }
    }

    client_initialized = 1;

    return RETURN_OK;
}

void wifi_client_event_callback_register(wifi_client_event_callback callback_proc)
{
    clients_connect_cb = callback_proc;
    printf("Registering callback STA\n");
    if (!client_initialized)
        init_client_wpa();
}

INT wifi_getSTANetworks(INT apIndex, wifi_sta_network_t **out_staNetworks_array, INT out_array_size, BOOL *out_scan_cur_freq)
{
    FILE *fd      = NULL;
    char fname[100];
    char * line = NULL;
    char * pos = NULL;
    size_t len = 0;
    ssize_t read = 0;
    int id = 0;
    int ret = 0;
    char * k;
    char * v;
    char *kv;
    wifi_sta_network_t * staNetwork;

    
   if(out_array_size <= 0 )
            return RETURN_ERR;

    char ssid_ifname[128];

    ret = wifi_getSTAName(apIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {   
        return RETURN_ERR;
    }
    
    snprintf(fname, sizeof(fname), "/tmp/%s.conf", ssid_ifname);
    fd = fopen(fname, "r");
    if (!fd) {
        return RETURN_ERR;
    }
     
    staNetwork= *out_staNetworks_array;
    while ((read = getline(&line, &len, fd)) != -1) {
        if(!strncmp(line, "network={",strlen("network={"))) {
            read = getline(&line, &len, fd) ;
            staNetwork->id = id;
            while (strncmp(line,"}",1)) {
                if ((k = strsep(&line, "=")) &&
                    (v = strsep(&line, ""))) {
                    if (!strcmp(k, "\tssid"))
                    {
                        v++; //skip quote
                        v = strsep(&v, "\"");
                        strncpy(staNetwork->ssid, v,32);
                    }
                    else if (!strcmp(k, "\tpsk"))
                    {
                        v++; //skip quote
                        v = strsep(&v, "\"");
                        strncpy(staNetwork->psk, v,128);
                    }
                    else if (!strcmp(k, "\tpairwise"))
                        strncpy(staNetwork->pairwise, v,64);
                    else if (!strcmp(k, "\tkey_mgmt"))
                        strncpy(staNetwork->key_mgmt, v,64);
                    else if (!strcmp(k, "\tproto"))
                    {
                        v = strsep(&v, "\n");
                        strncpy(staNetwork->proto, v,64);
                    }
                    else if (!strcmp(k, "\tbssid"))
                        sscanf(v, "%02x:%02x:%02x:%02x:%02x:%02x",
                               (unsigned int *)&staNetwork->bssid[0],
                               (unsigned int *)&staNetwork->bssid[1],
                               (unsigned int *)&staNetwork->bssid[2],
                               (unsigned int *)&staNetwork->bssid[3],
                               (unsigned int *)&staNetwork->bssid[4],
                               (unsigned int *)&staNetwork->bssid[5]);
                    else if (!strcmp(k, "multi_ap_backhaul_sta"))
                         staNetwork->multi_ap = atoi(v);
                } 
                if((read = getline(&line, &len, fd)) == -1)
                    break;
            }           
            id++;
            if(id >= out_array_size)
                goto close;
            staNetwork++;
            }
    }
close:
    fclose(fd);
    return RETURN_OK;
    
 
}

INT wifi_setSTANetworks(INT apIndex, wifi_sta_network_t **staNetworks_array, INT array_size, BOOL scan_cur_freq)
{
    FILE *fd = NULL;
    char fname[100];
    char cmd[128] = {0};
    char out[64] = {0};
    int ret = 0;
    char freq_list[] = "5180 5200 5220 5240 5745 5765 5785 5805";

    wifi_sta_network_t * sta = NULL;
    if(array_size < 0)
            return RETURN_ERR;
    char ssid_ifname[128];

    ret = wifi_getSTAName(apIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {
        return RETURN_ERR;
    }

    sprintf(cmd, "cp /tmp/%s.conf /tmp/%s.old", ssid_ifname, ssid_ifname);
    _syscmd(cmd, out, 64);

    snprintf(fname, sizeof(fname), "/tmp/%s.conf", ssid_ifname);
    fd = fopen(fname, "w");
    if (!fd) {
            return RETURN_ERR;
    }
    fprintf(fd, "ctrl_interface=%s\n", SOCK_PREFIX);
    fprintf(fd, "scan_cur_freq=%d\n", scan_cur_freq ? 1 : 0);

    sta = (wifi_sta_network_t *) *staNetworks_array;
    for(int i=0; i<array_size; ++i, sta++) {
        fprintf(fd, "network={\n");
        fprintf(fd, "\tscan_ssid=1\n");
        fprintf(fd, "\tbgscan=\"\"\n");
        fprintf(fd, "\tssid=\"%s\"\n", sta->ssid);
        fprintf(fd, "\tpsk=\"%s\"\n", sta->psk);
        fprintf(fd, "\tkey_mgmt=%s\n", sta->key_mgmt);
        fprintf(fd, "\tpairwise=%s\n", sta->pairwise);
        fprintf(fd, "\tproto=%s\n", sta->proto);
        fprintf(fd, "\t%s", strlen(sta->bssid) > 0 ? "" : "#");
        fprintf(fd, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n", sta->bssid[0],sta->bssid[1],sta->bssid[2],sta->bssid[3],sta->bssid[4],sta->bssid[5]);
        if((apIndex%2) && (strlen(sta->bssid) == 0))
        {
            //scan non dfs channel on 5G
            fprintf(fd, "\tscan_freq=%s\n", freq_list);
            fprintf(fd, "\tfreq_list=%s\n", freq_list);
        }
        fprintf(fd, "}\n");
    }
    fclose(fd);

    sprintf(cmd, "diff -q /tmp/%s.conf /tmp/%s.old", ssid_ifname, ssid_ifname);
    if(_syscmd(cmd, out, 64))
    {
        sprintf(cmd, "wpa_cli -B -i%s reconfigure", ssid_ifname);
        _syscmd(cmd, out, 64);
        if(apIndex%2)
        {
            wifi_setApEnable(1,false);
            wifi_setApEnable(3,false);
            wifi_setApEnable(5,false);
        }
        else
        {
            wifi_setApEnable(0,false);
            wifi_setApEnable(2,false);
            wifi_setApEnable(4,false);
        }
    }
    sprintf(cmd, "rm /tmp/%s.old", ssid_ifname);
    _syscmd(cmd, out, 64);

    return RETURN_OK;

}

INT wifi_getSTAEnabled(INT ssidIndex, BOOL *enabled)
{
    char ssid_ifname[128];
    char cmd[128] = {0};
    char out[64] = {0};
    int ret = 0;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {
        return RETURN_ERR;
    }

    sprintf(cmd, "wpa_cli -g/var/run/wpa_supplicant-global -i global status | grep %s", ssid_ifname);
    ret = _syscmd(cmd, out, 64);
    *enabled = ret == 0 ? true : false;

    return RETURN_OK;
}

INT wifi_setSTAEnabled(INT ssidIndex, BOOL enable)
{
    char ssid_ifname[128];
    char cmd[128] = {0};
    char out[64] = {0};
    int ret = 0;

    BOOL en;
    wifi_getSTAEnabled(ssidIndex,&en);
    if (enable == en)
        return RETURN_OK;

    ret = wifi_getSTAName(ssidIndex, ssid_ifname);
    if (ret != RETURN_OK)
    {   
        return RETURN_ERR;
    }

    if(enable)
    {
        sprintf(cmd, "wpa_cli -g/var/run/wpa_supplicant-global interface_add %s /tmp/%s.conf nl80211 /var/run/wpa_supplicant", ssid_ifname, ssid_ifname);
        ret = _syscmd(cmd, out, 64); 

    }
    else
    {
        sprintf(cmd, "wpa_cli -g/var/run/wpa_supplicant-global -i global interface_remove  %s", ssid_ifname);
        ret = _syscmd(cmd, out, 64);
    }

    return ret == 0 ? RETURN_OK : RETURN_ERR;
}
#endif
