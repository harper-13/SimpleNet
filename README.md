# Lab-2 

使用 Switchyard 框架实现以太网学习交换机的核心功能。交换机还将处理用于自身的帧以及以太网目标地址为广播地址的帧。除此之外，还将实现三种不同的机制来清除转发表中的过时/过时条目。这将使学习开关能够适应网络拓扑的变化。

# Lab-3

响应分配给路由器上接口的地址的 ARP（地址解析协议）请求。

# Lab-4 

1. 对没有已知以太网 MAC 地址的 IP 地址发出 ARP 请求。路由器通常必须向其他主机发送数据包，
并且需要MAC地址才能这样做。
2. 接收和转发到达链路并发往其他主机的数据包。转发过程的一部分是在转发信息库中执行地址查找
（“最长前缀匹配”查找）。您最终将只在路由器中使用“静态”路由，而不是实现 RIP 或 OSPF 等动
态路由协议。

# Lab-5 

1. 响应 ICMP 消息，如回显请求（“pings”）。
2. 必要时生成 ICMP 错误消息，例如当 IP 数据包的 TTL（生存时间）值已减少到零

# Lab-6

在 Switchyard 中构建一个可靠的通信库，该库将由 3 个代理组成。在高层次上，blaster将通过
middlebox向blastee发送数据包。由于IP只提供在主机之间传递数据包的尽力服务，这意味着一旦数据
包进入网络，就会发生各种不好的事情：它们可能会丢失、任意延迟或重复。您的通信库将通过在
blaster 和 blastee 上实现一些基本机制来提供额外的交付保证。
您的可靠通信库将实现以下功能以提供额外的保证：
1. blastee 上每个成功接收的数据包的 ACK 机制
2. blaster上的固定尺寸滑动窗口。
3. blaster上的粗略超时以重新发送非 ACK 数据包
