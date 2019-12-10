package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 网络
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum NetworkEnum {
    /**
     * 网络字段key及示意
     */
    HTTP("http", "HTTP"), TCP("tcp", "TCP"),
    IP("ip", "IP"), MAC("mac", "MAC"),
    WEB("web", "WEB"), INTERNET_IMEX("internet_imex", "互联网进出口"),
    LINK_STATU("link_statu", "链路状态"), INTERFACE("interface", "接口"),
    EXCHANGE("exchange", "交换"), UDP("udp", "UDP"),
    VPN("vpn", "VPN"), SESSION("session", "SESSION"),
    PUBLIC_NETWORK("public_network", "公网"), PRIVATE_NETWORK("private_network", "私网"),
    ADDRESS_MAPPING("address_mapping", "地址映射"), MESSAGE("message", "报文"),
    HA("ha", "HA"), CONTENT("content", "内容"),
    SCAN_INFO("scan_info", "扫描信息"), ACCESS_CONTROL("access_control", "访问控制"),
    MONITORING("monitoring", "监控"), PACKET_FILTER("packet_filter", "包过滤"),
    URL("url", "URL"), FILE("file", "文件"),
    ADS("ads", "ADS"), CONNECTION("connection", "连接"),
    IPS("ips", "IPS"), COMMUNICATION("communication", "通信"),
    APT("apt", "APT"), DATA_PACKET("data_packet", "数据包"),
    VIRTUAL("virtual", "虚拟"), PORT("port", "端口"),
    ROUTE("route", "路由"), APPLY("apply", "应用"),
    PRIVATE_CLOUD("private_cloud", "私有云"), INTERNET_BEHAVIOR("internet_behavior", "上网行为"),
    SSL("ssl", "SSL"),DATABASE("database","数据库"), OTHER("other", "其他");

    private String key;
    private String value;

    NetworkEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
