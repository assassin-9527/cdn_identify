# CDN_IDENTIFY

一款识别域名是否使用cdn的工具



## 背景

红队打点时经常会有收集子域名然后转成ip进而扩展ip段进行脆弱点寻找的需求，如果域名使用cdn，会导致收集错误的ip段，因此我们需要排除cdn来收集更准确的ip地址。

现有的一些识别cdn的工具存在如下问题：

- *仅根据cname或ip范围判断cdn，cname与ip范围不全导致遗漏*

- *输出字段较多，不方便直接与其他工具结合*



本工具是 https://github.com/alwaystest18/cdnChecker.git 的python版，原版是go语言的写的，因为个人平时python用的更多，所以将该工具用python写了一份。



## 安装使用

```
git https://github.com/assassin-9527/cdn_identify.git
cd cdn_identify/
pip3 install -r requirement.txt
python3 ./cdn_identify.py --domain www.baidu.com
```



## 使用

参数说明

```
Usage of cdn_identify.py:
  --domain string         //要测试的域名
        The target domain
  --domains string         //要测试的域名列表文件
        The target domain list file path
  -o string         //输出文件，默认为out.txt
        Toutput domains cdn check result to file
```

使用命令

```
$ cat domains.txt 
www.baidu.com
www.qq.com
www.alibabagroup.com
aurora.tencent.com

python3 ./cdn_identify.py --domain www.baidu.com
或者
python3 ./cdn_identify.py --domains domains.txt

cat out.txt
# 使用cdn的域名列表
www.baidu.com
www.qq.com
www.alibabagroup.com

# 未使用cdn的域名列表
aurora.tencent.com

# 未使用cdn的ip列表
43.137.23.148

runtime: 11s 
```


**强烈推荐dns服务器列表使用自带的resolvers（均为国内dns服务器且验证可用），如果服务器数量过少，大量的dns查询会导致timeout，影响查询准确度**



## 识别cdn思路

1.参考 go语言自带库 https://github.com/projectdiscovery/dnsx 的checkCdn方法（通过ip范围判断，主要为国外cdn厂商，对国内cdn识别效果不理想）

2.存在A记录但不存在cname的域名直接判断未使用cdn

3.存在cname的与cdn name列表对比，如果包含cdn cname列表则判断使用cdn

4.主要通过多个dns服务器节点获取域名解析ip，如果存在4个以上不同的ip段，则判断使用cdn，反之未使用cdn。



## 常见问题

结果中使用cdn域名列表与未使用cdn域名列表数量相加与实际测试域名数量不符？

答：对于无法获取解析ip的域名，程序会默认为域名无效过滤掉



## 感谢

https://github.com/alwaystest18/cdnChecker.git

https://github.com/xiaoyiios/chinacdndomianlist
