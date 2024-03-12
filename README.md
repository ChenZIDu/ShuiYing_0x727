# 水影-域信息收集（魔改版）
[![GitHub release](https://img.shields.io/github/release/0x727/ShuiYing_0x727.svg)](https://github.com/0x727/ShuiYing_0x727/releases)
郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 0x01 介绍

原作者：[Ske](https://github.com/SkewwG)
团队：[0x727](https://github.com/0x727)，未来一段时间将陆续开源工具，地址：https://github.com/0x727
定位：协助红队或甲方人员评估域环境的安全性
功能：**检测域环境内，域机器的本地管理组成员是否存在弱口令和通用口令，对域用户的权限分配以及域内委派查询**
原项目地址：https://github.com/0x727/ShuiYing_0x727


## 更新内容

* 优化了委派输出格式
* 修改为三种委派的机器查询和账户查询
* 新增了 CVE-2022-33679漏洞检测

```
Usage: <DC-IP> <DC> <domainname\\username> <password> <nbpassword> <t_num>
	\\域控IP 域控名 域名\\域用户 域用户密码 本地administrator通用密码 多线程数目
svchost.exe \\10.10.10.10 redteam.com redteam\susan asd123= null 1       //只查委派
svchost.exe\\192.168.159.149 redteam.com redteam\PC10$ NULL 123456 1   //只查通用密码
svchost.exe \\192.168.159.149 redteam.com redteam\lili li123!@#45 123456 1

如果当前用户是域用户，且没有该域用户的密码，则password输入NULL，如果当前用户是域机器的system权限，域用户名为主机名，password输入NULL，如果没有本地administrator通用密码，则nbpassword输入123456

```



