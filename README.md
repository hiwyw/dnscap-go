# Readme
## 说明
DNS抓包日志及分析工具，支持基于离线抓包文件或实时在线抓包生成dns日志以及dns统计
## 配置
```yaml
source_type: packet_file # packet_file或packet_capture，分别表示离线抓包文件分析或在线实时抓包分析运行方式
source_pcap_files: # 需要分析的抓包文件列表，按时间顺序填写配置，仅用于packet_file方式
  - dns.pcap00
  - dns.pcap01
  - dns.pcap02
source_device_name: ens33 # 抓包网卡名称，仅用于packet_capture方式
filter_ips: [] # 过滤ip列表，用于只分析名单中的ip，通过设置抓包条件实现，为空时分析所有udp 53报文
output_dir: ./dnscap_result #
self_ips: # dns服务器自身ip列表，用于判断报文是客户端侧报文还是服务端自身出向递归报文
  - 192.168.134.200
  - 192.168.135.200
worker_count: 1 # 数据包解析工作线程数，可通过修改此数值提升处理性能
session_cache_size: 20000 # 请求会话缓存大小，底层实现根据transid进行了缓存分区，配置为每个分区缓存的大小，保持默认即可
dnslog_enable: true # 是否输出dns日志
dnslog_filename: dns.log # 输出的dns日志文件名称
dnslog_maxsize: 50 # 输出的dns日志文件大小，单位MB
dnslog_count: 100 # 输出的dns日志文件最大数量，单位个，超出后会自动轮滚
dnslog_age: 30 # 输出的日志文件最大保留天数，按照轮滚后的压缩文件名称判断清理
analyze_enable: false # 是否输出dns统计
analyzeOutFilename: analyze.log # 输出的dns统计文件名称
analyze_interval: 5m # dns统计周期，注意统计使用报文中的时间，因此离线文件分析时，请务必保证文件按时间前后进行排列
analyze_querycount_ips: # 统计特定ip的列表，可输出指定ip的请求、响应数、延时分布信息
  - 192.168.134.201
  - 192.168.134.202
analyze_querycount_domains: # 统计特定域名的列表，可输出指定域名的请求、响应数、延时分布信息
  - www.test.com.
run_log_filename: run.log # 程序自身运行日志文件名称
pprof_enable: false # 程序性能分析开关，保持默认关闭即可
pprof_http_port: 8000 # 程序性能分析http服务端口，默认即可
```
## 日志格式
示例日志：
```
2023-08-30 16:03:20.467226|10.1.136.253|192.168.219.22|53|58938|18900|response|www.qq.com.|IN|A|NOERROR|1|0|1|1|0|5160|www.qq.com. 248 IN CNAME ins-r23tsuuf.ias.tencent-cloud.net.;ins-r23tsuuf.ias.tencent-cloud.net. 38 IN A 221.198.70.47||;; OPT PSEUDOSECTION:; EDNS: version 0; flags:; udp: 4096; SUBNET: 1.1.1.0/24/0
```
从前往后字段依次为：
* 时间
* 源IP
* 目的IP
* 源端口
* 目的端口
* transid
* 报文类型，请求报文为query，响应报文为response
* 域名
* queryclass，固定IN
* 请求类型
* 解析状态rcode
* 权威标志位，Authoritative，1设置，0不设置
* 截断标志位，Truncated，1设置，0不设置
* 递归标志位，RecursionDesired，1设置，0不设置
* 递归可用标志位，RecursionAvailable，1设置，0不设置
* Zero标志位
* 解析时延，单位微秒
* 应答段内容，Answer，单rr字段见空格分隔，多条rr间分号分隔
* 权威段内容，Authority，单rr字段见空格分隔，多条rr间分号分隔
* 附加段内容，Additional，单rr字段见空格分隔，多条rr间分号分隔

## 统计日志格式
* begin_time：开始统计时间
* end_time：结束统计时间
* client_side：客户端侧统计
* recursion_side：服务端出向递归侧统计
* special_ips：特定ip统计
* special_domains：特定域名统计
* query_count：请求报文数
* reponse_count：响应报文数
* delay_statistics：解析时延统计
* rcode_statistics：解析状态统计
* qtype_statistics：请求类型统计


```json
{
    "begin_time": "2023-08-29T22:14:18.74508+08:00",
    "end_time": "2023-08-29T22:15:18.74508+08:00",
    "client_side": {
        "query_count": 4078,
        "response_count": 3778,
        "delay_statistics": {
            "0-10ms": 3736,
            "10-100ms": 42,
            "100-1000ms": 0,
            "1000-3000ms": 0,
            "3000ms+": 0
        },
        "rcode_statistics": {
            "NOERROR": 3775,
            "NXDOMAIN": 3
        },
        "qtype_statistics": {
            "A": 3778
        }
    },
    "recursion_side": {
        "query_count": 0,
        "response_count": 0,
        "delay_statistics": {
            "0-10ms": 0,
            "10-100ms": 0,
            "100-1000ms": 0,
            "1000-3000ms": 0,
            "3000ms+": 0
        }
    },
    "special_ips": {
        "192.168.144.201": {
            "query_count": 4007,
            "response_count": 3707,
            "delay_statistics": {
                "0-10ms": 3665,
                "10-100ms": 42,
                "100-1000ms": 0,
                "1000-3000ms": 0,
                "3000ms+": 0
            }
        }
    },
    "special_domains": {
        "1.test.com.": {
            "query_count": 0,
            "response_count": 0,
            "delay_statistics": {
                "0-10ms": 0,
                "10-100ms": 0,
                "100-1000ms": 0,
                "1000-3000ms": 0,
                "3000ms+": 0
            }
        },
        "2.test.com.": {
            "query_count": 4,
            "response_count": 3,
            "delay_statistics": {
                "0-10ms": 3,
                "10-100ms": 0,
                "100-1000ms": 0,
                "1000-3000ms": 0,
                "3000ms+": 0
            }
        }
    }
}
```

## 使用方式
```bash
./dnscap-go -config config.yaml
```