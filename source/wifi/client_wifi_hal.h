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
#ifndef __CLIENT_WIFI_HAL_H__
#define __CLIENT_WIFI_HAL_H__
INT wifi_getSTANumberOfEntries(ULONG *output);
INT wifi_getSTAName(INT apIndex, CHAR *output_string);
INT wifi_getSTARadioIndex(INT ssidIndex, INT *radioIndex);
INT wifi_getSTAMAC(INT ssidIndex, CHAR *output_string);
INT wifi_getSTABSSID(INT ssidIndex, CHAR *output_string);
INT wifi_getSTASSID(INT ssidIndex, CHAR *output_string);
INT wifi_getSTACredentials(INT ssidIndex, CHAR *output_string);
INT wifi_getSTANetworks(INT apIndex, wifi_sta_network_t **out_staNetworks_array, INT out_array_size, BOOL *out_scan_cur_freq);
INT wifi_setSTANetworks(INT apIndex, wifi_sta_network_t **staNetworks_array, INT array_size, BOOL scan_cur_freq);
INT wifi_getSTAEnabled(INT ssidIndex, BOOL *enabled);
INT wifi_setSTAEnabled(INT ssidIndex, BOOL enable);
#endif
