# design
## 背景
* 存在众多项目使用开源DNS，替换时无业务量评估依据，有业务流量评估工具需求
* 当前版本不支持出向递归日志及监控，部分项目有此需求，排期开发周期较长，此外对于历史版本项目也需要有支持方法

## 目标
* 功能层面支持输出DNS日志、简单的统计内容（客户端侧请求次数、服务端递归请求次数、指定IP的请求数、超过指定时间时延的请求数（客户端、服务端）、分rcode请求数（客户端）、客户端IP总数）
* 输入源支持离线抓包文件和指定网卡实时抓包
* 支持对输入源数据进行过滤，只输出统计指定IP的数据
* 支持输出的日志文件轮滚，但不支持压缩及备份外发
* 提供脚本工具实现对输出日志文件的轮滚及备份外发

## 设计
### 配置文件

* 格式：yaml
* 配置项
    * source_type: pcap_file、packet_capture
    * source_pcap_files: 输入的抓包文件列表，数组
    * source_device_name: 网卡名称
    * filter_ips: 过滤的ip列表
    * outout_dir: 输出文件目录
    * output_dnslog_file: 输出dns日志文件名称
    * output_analyze_file: 输出dns分析文件名称
    * analyze_enable: true false
    * analyze_interval: 5m
    * analyze_delay_threshold: 3s
    * analyze_query_count_ips: 指定ip的qps，ip数组
    * self_ips: 抓包所在设备自身的所有IP
    * worker_count: 1
    * session_cache_size: 65535

### 源数据读取
源数据读取采用单线程设计，读取到数据包后就传入一个channel，源数据读取根据配置的source_type来决定使用gopacket的Offline方法还是OpenLive方法

### 数据包解析
使用google/gopacket和miekg/dns两个库实现对dns数据包的解析，输出相关日志，日志格式为json或|分隔

解析后的dns packet结构体为：
```go
type DnsLog struct {
	QueryTime          time.Time
	SrcIP              net.IP
	DstIP              net.IP
	SrcPort            uint16
	TransID            uint16
	Domain             string
	QueryClass         string
	QueryType          string
	Rcode              string
	Response           bool
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	ResolvDuration     time.Duration
	Answer             []string
	Authority          []string
	Additional         []string
}
```

其中QueryTime从数据包元信息中获取、SrcIP、DstIP从IP层获取、SrcPort从UDP层获取，剩余字段通过miekg/dns Msg解析得到

### WorkerPool
WorkerPool主要用于加速数据包解析处理及日志格式化等环节，每个worker有多个handler，完成数据包解析后，会将结构化的dns包传递至自身的handler，由handler完成后续日志格式化输出及分析统计

### Handler
#### DnslogHandler


#### AnalyzeHandler

