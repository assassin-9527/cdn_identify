import requests
import json
import netaddr
import socket
import argparse
import datetime
import threading
import collections
import time
from numpy import random
from dns import resolver, rdatatype


# cdn cname文件路径
cdn_cname_file_path = "cdn_cname"
# dns服务器列表文件路径
resolvers_file_path = "resolvers"
# 可用dns服务器的最小个数
min_resolvers_count = 20

def read_file2arr(file_path):
    """
    读取文件并以'\n'换行符拆分为数组返回
    """
    with open(file=file_path, mode="r", encoding="utf-8") as fd:
        return fd.readlines()


def unique_strlist(str_list:list):
    """
    字符列表去重去空
    """
    tmp_list = []
    for str_val in str_list:
        str = str_val.strip()
        if str:
            tmp_list.append(str)
    return set(tmp_list)


class CdnCheck:
    def __init__(self, resolvers:list, cdn_name_list:list, cache=True) -> None:
        self.cache = cache
        self.ranges = {}
        self.rangers = {}
        self.resolvers = resolvers
        self.cdn_name_list = cdn_name_list
        if cache:
            self.getCDNDataFromCache()
        else:
            self.getCDNData()
        self.no_cdn_domains = [] # 未使用cdn的域名列表
        self.use_cdn_domains = [] # 使用cdn的域名列表
        self.no_cdn_ips = [] # 未使用cdn的ip列表
    
    def write_data2file(self, out_file_path, runtime):
        with open(file=out_file_path, mode="w", encoding="utf-8") as fd:
            if self.use_cdn_domains:
                fd.write("# 使用cdn的域名列表\n")
                fd.writelines('\n'.join(set(self.use_cdn_domains)))
                fd.write("\n\n")
            if self.no_cdn_domains:
                fd.write("# 未使用cdn的域名列表\n")
                fd.writelines('\n'.join(set(self.no_cdn_domains)))
                fd.write("\n\n")
            if self.no_cdn_ips:
                fd.write("# 未使用cdn的ip列表\n")
                fd.writelines('\n'.join(set(self.no_cdn_ips)))
                fd.write("\n\n")
            fd.write(f'runtime: {runtime}s\n')


    def getCDNDataFromCache(self):
        self.ranges = self.scrapeProjectDiscovery()
        if self.ranges:
            for provider, ranges in self.ranges.items():
                network_list = []
                for cidr in ranges:
                    network = netaddr.IPNetwork(cidr)
                    network_list.append(network)
                self.rangers[provider] = network_list

    def getCDNData(self):
        pass

    def scrapeProjectDiscovery(self):
        data = {}
        try:
            resp = requests.get("https://cdn.nuclei.sh")
            data =json.loads(resp.text)
        except:
            pass
        return data
    
    def InCdnCnameList(self, domain_cname_list):
        for domain_cname in domain_cname_list:
            for cdn_cname in self.cdn_name_list:
                if domain_cname in cdn_cname:
                    return True
        return False
    
    def generateRandomNumber(self,start:int, end:int, count:int):
        return random.randint(start, end, count)
    
    # 获取域名在特定dns上的解析ip，并且以.分割ip，取ip的前三部分，即解析ip为1.1.1.1,最终输出为[1.1.1],便于判断多个ip是否在相同网段
    def resolvDomainIpPart(self, domain:str, name_server:str):
        domain_ips_part = []
        resolverList = [name_server]
        dns_client = resolver.Resolver()
        dns_client.nameservers = resolverList
        try:
            answers = dns_client.query(qname=domain, rdtype = rdatatype.A)
            ips_list = []
            for rdata in answers:
                ips_list.append(rdata.address)
            if len(ips_list) > 0:
                for ip in ips_list:
                    ip_parts = ip.split(".")
                    ip_split = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2]
                    domain_ips_part.append(ip_split)
        except:
            pass
        return domain_ips_part


    def range_check(self, domain):
        ip = socket.gethostbyname(domain)
        for provider, ranger in self.rangers.items():
            for network in ranger:
                if ip in network:
                    return True, provider
        return False, ""

    def cname_check(self, domain):
        if self.resolvers:
            domain_ip_list = []
            domain_cname_list = []
            try:
                dns_client = resolver.Resolver()
                dns_client.nameservers = self.resolvers
                answers = dns_client.query(qname=domain, rdtype = rdatatype.A)
                for answ in answers.response.answer:
                    for item in answ.items:
                        if item.rdtype == rdatatype.A:
                            domain_ip_list.append(item.to_text())
                        elif item.rdtype == rdatatype.CNAME:
                            domain_cname_list.append(item.to_text().rstrip(".")) # 去掉域名最后的点
            except:
                pass
            if len(domain_cname_list) == 0 and len(domain_ip_list) > 0:
                # 无cname但有A记录，直接判定未使用cdn
                self.no_cdn_domains.append(domain)
                self.no_cdn_ips.extend(domain_ip_list)
            elif len(domain_cname_list) > 0 and len(domain_ip_list) > 0:
                if self.InCdnCnameList(domain_cname_list):
                    # cdn在cdn cname列表中包含，直接判定使用cdn
                    self.use_cdn_domains.append(domain)
                else:
                    domain_ip_part_list = []
                    domain_ip_part_count = 0
                    rand_nums = self.generateRandomNumber(0, len(self.resolvers), min_resolvers_count)
                    for num in rand_nums:
                        name_server = self.resolvers[num]
                        domain_ips_with_resolver = self.resolvDomainIpPart(domain=domain, name_server=name_server)
                        domain_ip_part_list.extend(domain_ips_with_resolver)
                        domain_ip_part_count = len(unique_strlist(domain_ip_part_list))
                        if domain_ip_part_count > 3:
                            break
                    if domain_ip_part_count > 3:
                        # 不同段ip数量达到4个就判定为使用了cdn
                        self.use_cdn_domains.append(domain)
                    else:
                        self.no_cdn_domains.append(domain)
                        self.no_cdn_ips.extend(domain_ip_list)


        return False

    
    def Check(self, domain):
        if domain.strip():
            is_cdn, _ = self.range_check(domain)
            if is_cdn:
                self.use_cdn_domains.append(domain)
            self.cname_check(domain)



class WorkThread(object):
    def __init__(self, targets, concurrency=6):
        self.concurrency = concurrency
        self.semaphore = threading.Semaphore(concurrency)
        self._targets = targets
        self.result_list = []

    def work(self, target):
        raise NotImplementedError()

    def _work(self, target):
        try:
            ret_val = self.work(target)
            if ret_val:
                self.result_list.append(ret_val)
        except Exception as ex:
            # print(f"target:{target} [+] ", ex)
            pass

        except BaseException as ex:
            print("BaseException on {}".format(str(ex)))
            self.semaphore.release()
            raise ex
        self.semaphore.release()

    def _run(self):
        deque = collections.deque()
        for target in self._targets:
            if isinstance(target, str):
                target = target.strip()
            if not target:
                continue
            self.semaphore.acquire()
            t1 = threading.Thread(target=self._work, args=(target,))
            t1.start()
            deque.append(t1)

        for t in list(deque):
            while t.is_alive():
                time.sleep(0.2)
    
    def run(self):
        self._run()
        return self.result_list

def filter_valid_resolvers(resolvers_list):
    # 通过解析特定域名获取ip地址来找出提供列表中可用dns服务器
    def __filter_valid_worker(name_server):
        try:
            dns_client = resolver.Resolver()
            dns_client.nameservers = [name_server]
            dns_client.lifetime = 5
            answers = dns_client.query(qname="public1.114dns.com", rdtype = rdatatype.A)
            for rdata in answers:
                if "114.114.114.114" == rdata.address:
                    return name_server
        except:
            pass
    work_th = WorkThread(resolvers_list, len(resolvers_list))
    work_th.work = __filter_valid_worker
    work_th.run()
    return work_th.result_list




arg_parser = argparse.ArgumentParser() 
domains_parser = arg_parser.add_mutually_exclusive_group(required=True)
domains_parser.add_argument('--domain', dest="domain", type=str, help="The target domain")
domains_parser.add_argument('--domains', dest="domains", type=str, help="The target domain list file path")
arg_parser.add_argument('-o', dest="out_path", type=str, default="out.txt", help="Toutput domains that are not using cdn to file")
args = arg_parser.parse_args()
if __name__ == "__main__":
    starttime = datetime.datetime.now()
    cdn_cname_list = unique_strlist(read_file2arr(cdn_cname_file_path))
    temp_resolvers_list = unique_strlist(read_file2arr(resolvers_file_path))
    resolvers_list = filter_valid_resolvers(temp_resolvers_list)
    
    if len(resolvers_list) < min_resolvers_count:
        print("The number of valid resolvers is less than 20, please improve it: resolvers")
        exit(2)
    check_obj = CdnCheck(resolvers=resolvers_list, cdn_name_list=cdn_cname_list)
    if args.domain:
        check_obj.Check(domain=args.domain)
    elif args.domains:
        domains_list = unique_strlist(read_file2arr(args.domains))
        work_th = WorkThread(domains_list, len(domains_list))
        work_th.work = check_obj.Check
        work_th.run()
    endtime = datetime.datetime.now()
    runtime = (endtime - starttime).seconds
    check_obj.write_data2file(args.out_path, runtime)
