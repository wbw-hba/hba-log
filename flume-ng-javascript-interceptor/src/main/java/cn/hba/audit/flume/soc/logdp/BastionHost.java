package cn.hba.audit.flume.soc.logdp;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.lang.Validator;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 接入防火墙与负载交互
 * 接入防火墙	迪普DPtech FW1000-TA-N
 * 应用交付/负载均衡	迪普DPtech DPX8000-A12
 *
 * @author wbw
 * @date 2019/9/6 16:55
 */
public class BastionHost {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");

        syslog = syslog.replaceAll("dptech", "DPTECH");
        int length = syslog.split("\\|").length;
        if (syslog.contains("|") && length >= 7) {
            // syslog 格式一
            if (length == 8) {
                syslog1(syslog, obj);
            } else if (length == 7 && syslog.contains(" ")) {
                // 遗弃 syslog 格式6
                // ipv4、ipv6 及 syslog4 处理
                syslog2Ipv46(syslog, obj);
            }
        } else if (syslog.contains("DPTECH") && syslog.contains("%%") && syslog.contains("start_time=") && syslog.contains("):")) {
            syslog7(syslog, obj);
        } else if (syslog.contains("DPTECH") && syslog.contains("%%") && syslog.contains("):")) {
            syslogParse1(syslog, obj);
            if (!obj.containsKey("event_type")) {
                obj.put("event_type", syslog.split("%%")[1].split("/")[1]);
            }
        } else if (syslog.contains("traffic") && syslog.contains("start_time") && syslog.contains("src")
                && syslog.contains("dst") && syslog.contains("dst_port") && syslog.contains("ip")
                && syslog.contains("reason")) {
            syslog4(syslog, obj);
        } else if (syslog.contains("Slot:")) {
            // 2.12端口块消耗尽日志 Syslog日志格式
            syslogWarning(syslog, obj);
        } else if (syslog.contains(" [") && syslog.contains("]") && syslog.contains("Session")) {
            // syslog 格式 3 和 5
            // NAT46 格式
            syslog35(syslog, obj);
        } else {
            return null;
        }


        if ("fw".equalsIgnoreCase(obj.getStr("app_name"))) {
            // 日志类型 接入防火墙
            obj.put("log_des", "迪普 - 接入防火墙");
            obj.put("log_type", "firewall");
        } else {
            obj.put("log_des", "迪普 - 负载交互");
            obj.put("log_type", "equilibrium");
        }

        return obj;
    }

    /**
     * 格式：<142> 1 1.1.1.1 2013 Nov 26 11:43:16 Warning!Slot:8 The Port utilization rate has reached 100%.
     */
    private static void syslogWarning(String syslog, JSONObject obj) {
        String[] warnings = syslog.split("Slot:")[0].split(" ");
        obj.put("device_version", warnings[1]);
        obj.put("hostname", warnings[2]);
        // 事件类型
        obj.put("event_type", "warning");
        obj.put("event_level", "4");
        obj.put("message_content", warnings[warnings.length - 1]);
        String msg = syslog.split("Slot:")[1];
        obj.put("slot", msg.substring(0, msg.indexOf(" ")));
        obj.put("message_content_explain", msg.substring(msg.indexOf(" ")));
    }

    /**
     * 格式：Apr 22 07:29:39 2015 DPTECH %%--FW/SESSION/5/SYSLOG(7): traffic start_time="2015-04-22 07:29:39"
     * duration=132 service=ICMP/port:80 proto=1 sent=10124 rcvd=10124 src=10.28.6.6
     * dst=8.8.8.2 src_port=7 dst_port=89 src-xlated ip=8.8.8.1 port=3 dst-xlated ip=8.8.8.2 port=1500 reason=Close - ICMP TIMEOUT.
     */
    private static void syslog7(String syslog, JSONObject obj) {
        String[] head = syslog.split("traffic")[0].split("DPTECH ")[1].split("/");
        syslog4(syslog, obj);
        obj.remove("hostname");
        obj.put("device_type", head[0].replaceAll("%", "").replaceAll("-", ""));
        obj.put("event_type", head[1].toLowerCase());
        obj.put("event_level", head[2]);
        obj.put("procid", "syslog7");
    }

    /**
     * 格式：<142> 1.1.1.1 2013 Nov 26 11:43:16 traffic start_time="1970-01-01 08:14:40"
     * duration=132 service=ICMP/port:80 proto=1 sent=10124 rcvd=10124 src=10.28.6.6
     * dst=8.8.8.2 src_port=7 dst_port=89 src-xlated ip=8.8.8.1 port=3 dst-xlated ip=8.8.8.2 port=1500 reason=Close - ICMP TIMEOUT.
     */
    private static void syslog4(String syslog, JSONObject obj) {
        String[] split = syslog.replace(" src-xlated", "")
                .replace(" dst-xlated", "").split("traffic");
        String[] head = split[0].split(" ");
        obj.put("hostname", head[1]);
        obj.put("app_name", "traffic");
        obj.put("event_type", "traffic");
        String[] msg = split[1].replace("=\"", "=").split("=");
        obj.put("start_time", msg[1].substring(0, msg[1].indexOf("\" ")));
        // 持续时间（以秒为单位）
        obj.put("duration_time", msg[2].split(" ")[0]);
        // 转换前目的协议名称
        String[] service = msg[3].split("/port:");
        obj.put("original_destination_protocol", service[0]);
        // 转换前目的端口0-65535
//        obj.put("original_destination_port", service[1].split(" ")[0]);
        // 发送的报文字节数
        obj.put("send_bytes", msg[5].split(" ")[0]);
        // 接收的报文字节数
        obj.put("received_bytes", msg[6].split(" ")[0]);

        obj.put("original_source_ip", msg[7].split(" ")[0]);
        obj.put("original_destination_ip", msg[8].split(" ")[0]);
        obj.put("original_source_port", msg[9].split(" ")[0]);
        obj.put("original_destination_port", msg[10].split(" ")[0]);
        obj.put("translated_source_ip", msg[11].split(" ")[0]);
        obj.put("translated_source_port", msg[12].split(" ")[0]);
        obj.put("translated_destination_ip", msg[13].split(" ")[0]);
        obj.put("translated_destination_port", msg[14].split(" ")[0]);

        String[] reason = msg[msg.length - 1].split(" - ");
        obj.put("flow_type", "close".equalsIgnoreCase(reason[0]) ? "关闭" : "新建");
        if (reason[1].split(" ").length > 1) {
            String flowEndFlag = reason[1].split(" ")[1];
            obj.put("flow_end_flag", "fin".equalsIgnoreCase(flowEndFlag) ? "正常结束" : "超时结束");
        }
        obj.put("procid", "syslog4");
    }

    /**
     * 格式：<134> 1 2013 Nov 26 11:46:51 172.254.100.10 FW NAT444:SessionW [6 10.22.24.13 - 106.120.238.99 53287 32075 32075]
     * 格式：<134> 1 2013 Nov 26 11:46:51 172.254.100.10 FW - NAT444:SessionbasedW [6 10.22.24.13 – 106.120.238.99 – 32075 32075]
     * 格式：<134> 1 2013 Nov 26 11:46:51 172.254.100.10 FW - DSLITE:SessionbasedW [6 – 10:0:0:0:0:0:0:98 106.120.238.99 53287 32075 -]
     * 格式：<142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT444:SessionW [6 - 12:0:0:0:0:0:0:56 8.8.8.1 7 3 3].
     * 格式：<142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT64:SessionW [6 - 8.8.8.1 2001:0:0:0:0:0:0:1 7 3 3]
     */
    private static void syslog35(String syslog, JSONObject obj) {
        String[] split = syslog.split(" \\[");
        String[] head = split[0].split(" ");
        int tail = head.length == 10 ? 1 : 0;

        obj.put("device_version", head[1]);
        if (Validator.isIpv4(head[2])) {
            obj.put("hostname", head[2]);
            obj.put("procid", "NAT64");
        } else {
            obj.put("hostname", head[head.length - 3 - tail]);
            obj.put("procid", syslog.contains("based") ? "syslog3" : "syslog5");
        }

        obj.put("app_name", head[head.length - 2 - tail]);
        String[] msgId = head[head.length - 1].trim().split(":");
        obj.put("device_type", msgId[0]);
        obj.put("event_type", msgId[1]);

        String[] mes = split[1].split(" ");
        for (int i = 0; i < mes.length; i++) {
            if (i == 0) {
                int dp = NumberUtil.parseInt(mes[i]);
                obj.put("destination_protocol", dp == 1 ? "ICMP" : dp == 6 ? "TCP" : "UDP");
            } else if (i == 1) {
                if (Validator.isIpv6(mes[i])) {
                    obj.put("original_source_ipv6", "–".equalsIgnoreCase(mes[i]) ? "" : mes[i]);
                } else {
                    obj.put("original_source_ip", "–".equalsIgnoreCase(mes[i]) ? "" : mes[i]);
                }
            } else if (i == 2 || i == 3) {
                if (Validator.isIpv6(mes[i])) {
                    obj.put("original_source_ipv6", "–".equalsIgnoreCase(mes[i]) ? "" : mes[i]);
                } else {
                    obj.put("translated_source_ip", mes[i]);
                }
            } else if (i == mes.length - 3) {
                obj.put("original_source_port", "–".equalsIgnoreCase(mes[i]) ? "" : mes[i]);
            } else if (i == mes.length - 2) {
                obj.put("translated_source_port", "–".equalsIgnoreCase(mes[i]) ? "" : mes[i]);
            } else if (i == mes.length - 1) {
                obj.put("translated_source_last_port", ("–".equalsIgnoreCase(mes[i]) ? "" : mes[i]).split("]")[0]);
            }
        }

    }

    /**
     * 格式： <142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT444:SessionW 19700101081609|10.28.6.6|6949|8.8.8.1|28920|8.8.8.2|80
     * 格式：<142> 1 10.28.6.17 1970 Jan 01 08:39:06 FW 23 POLICY:Allow  6|10.1.249.2|1024|8.8.8.1|80|gige0_1|gige0_2
     * 格式：<142> 1 10.28.6.17 1970 Jan 01 08:39:06 FW 123 POLICY: Allow  6|1:0:0:0:0:0:0:128|1024|2:0:0:0:0:0:0:1|80|gige0_1|gige0_2
     */
    private static void syslog2Ipv46(String syslog, JSONObject obj) {
        String[] split = syslog.replaceAll("POLICY: ", "POLICY:").split("\\|");
        // 包过滤日志
        boolean packageMsg = syslog.contains("Allow") || syslog.contains("Deny");
        for (int i = 0; i < split.length; i++) {
            if (i == 0) {
                syslogHeader(split[i], obj);
                String[] header = split[i].split(" ");
                obj.remove("start_time");
                if (packageMsg) {
                    int protocol = NumberUtil.parseInt(header[header.length - 1]);
                    obj.put("destination_protocol", protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "ICMP");
                } else {
                    obj.put("start_time", DateUtil.parse(header[header.length - 1]).toString());
                }
            } else if (i == 1) {
                obj.put("source_ip", split[i]);
            } else if (i == 2) {
                obj.put("src_port", split[i]);
            } else if (i == 3) {
                if (packageMsg) {
                    obj.put("destination_ip", split[i]);
                } else {
                    obj.put("translated_source_ip", split[i]);
                }
            } else if (i == 4) {
                if (packageMsg) {
                    obj.put("destination_port", split[i]);
                } else {
                    obj.put("translated_source_port", split[i]);
                }
            } else if (i == 5) {
                if (packageMsg) {
                    obj.put("in_ifname", split[i]);
                } else {
                    obj.put("destination_ip", split[i]);
                }
            } else if (i == 6) {
                if (packageMsg) {
                    obj.put("out_ifname", split[i]);
                } else {
                    obj.put("destination_port", split[i]);
                }
            }
        }
        obj.put("procid", packageMsg ? "syslog2Ipv46" : "syslog2");
    }

    /**
     * 格式：<142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT444:SessionW 1320370756|1320370759|10.1.249.2|124.207.3.12|10256|219.207.3.12|80|6
     */
    private static void syslog1(String syslog, JSONObject obj) {
        String[] split = syslog.split("\\|");
        for (int i = 0; i < split.length; i++) {
            if (i == 0) {
                syslogHeader(split[i], obj);
            } else if (i == 1) {
                obj.put("end_time", DateUtil.date(NumberUtil.parseLong(split[i])).toString());
            } else if (i == 2) {
                obj.put("original_source_ip", split[i]);
            } else if (i == 3) {
                obj.put("translated_source_ip", split[i]);
            } else if (i == 4) {
                obj.put("translated_source_port", split[i]);
            } else if (i == 5) {
                obj.put("original_destination_ip", split[i]);
            } else if (i == 6) {
                obj.put("original_destination_port", split[i]);
            } else if (i == 7) {
                // 转换前目的协议类型（6为TCP，17为UDP，1为ICMP）
                int p = NumberUtil.parseInt(split[i]);
                String originalDestinationProtocol = p == 17 ? "UDP" : p == 1 ? "ICMP" : "TCP";
                obj.put("original_destination_protocol", originalDestinationProtocol);
            }
        }
        obj.put("procid", "syslog1");
    }

    /**
     * 头部解析
     */
    private static void syslogHeader(String syslog, JSONObject obj) {
        String[] header = syslog.split(" ");
        // 设备版本
        obj.put("device_version", header[1]);
        // 管理端口的IPv4地址
        obj.put("hostname", header[2]);
        for (int j = 2; j < header.length; j++) {
            if (j == header.length - 1) {
                obj.put("start_time", DateUtil.date(NumberUtil.parseLong(header[j])).toString());
            } else if (header[j].contains(":") && !obj.containsKey("app_name")) {
                // 设备名称
                obj.put("app_name", header[++j]);
            } else if (obj.containsKey("app_name") && !header[j].contains(":")) {
                // 日志组的编号
                obj.put("procid", header[j]);
            } else if (obj.containsKey("app_name") && !obj.containsKey("device_type")) {
                String[] msgId = header[j].trim().split(":");
                obj.put("device_type", msgId[0]);
                obj.put("event_type", msgId[1]);
            }
        }
    }

    /**
     * <12>2011-03-09 22:17:31 DPTECH %%--IPS/DEVM/4/SYSLOG(l): The temperature of mainboard [0] is too high: 41.
     * Jul  5 13:26:44 2009 DPTECH %%UAG/ATTACK/0/DATALOG(l): log-type(1):attack-protect;event(2):block;attack-name(11):(352325536)死亡之Ping;protocol-name(17):(50333952)IP;ip-proto-id(18):1;source-ip(24):192.168.1.154;source-port(25):0;destination-ip(26):192.168.1.254;destination-port(27):0;block-reason(28):ABNORMITY-DETECTION;ifname-inside(29):eth0/2;ifname-outside(30):eth0/2;summary-count(33):1;summary-offset(34):0;
     * <14>2019-09-19 15:42:18 DPTECH %%--DPX/WEB/6/OPERLOG(l): client-type(84):web;user-name(85):admin;host-ip(86):2.74.24.29;error-code(87):0;设置操作日志配置，开启发送到远程IPV4日志主机服务，远程日志主机地址：[2.74.24.29]，本机地址：[100.73.26.149]， 端口：[5141]。 result: Success.
     */
    private static void syslogParse1(String syslog, JSONObject obj) {
        obj.put("manufacturers_name", "dp");

        if (StrUtil.containsIgnoreCase(syslog, "SYSLOG")) {
            syslogParse2(syslog, obj);
            obj.put("message_content", syslog.split("\\%\\%\\-\\-")[1].split("/")[3].split(":")[1].trim());

        } else if (StrUtil.containsIgnoreCase(syslog, "OPERLOG")) {
            syslogParse2(syslog, obj);
            if (StrUtil.containsIgnoreCase(syslog, "client-type")) {
                obj.put("event_type", syslog.split("client-type")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "client-type")) {
                obj.put("user_name", syslog.split("user-name")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "host-ip")) {
                obj.put("source_ip", syslog.split("host-ip")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "error-code")) {
                obj.put("result", "0".equalsIgnoreCase(syslog.split("error-code")[1].split(":")[1].split(";")[0].trim()) ? "成功" : "失败");
            }
            obj.put("message_content", syslog.split(";")[4].trim());

        } else if (StrUtil.containsIgnoreCase(syslog, "DATALOG")) {

            obj.put("hostname", syslog.split(" ")[5].trim());

            obj.put("device_uuid", syslog.split("%%")[1].split("/")[0]);

            obj.put("log_type", syslog.split("%%")[1].split("/")[1]);

            obj.put("severity", syslog.split("%%")[1].split("/")[2]);

            if (StrUtil.containsIgnoreCase(syslog, "log-type")) {
                obj.put("log_type", syslog.split("log-type")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "event")) {
                obj.put("event_type", syslog.split("event")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "attack-name")) {
                obj.put("fw_rule_id", syslog.split("attack-name")[1].split(":")[1].split(";")[0].trim());
            }

            if (StrUtil.containsIgnoreCase(syslog, "av-name")) {
                obj.put("av_name", syslog.split("av-name")[1].split(":")[1].split(";")[0].trim());
            }

            if (StrUtil.containsIgnoreCase(syslog, "protocol-name")) {
                obj.put("app/protocol", syslog.split("protocol-name")[1].split(":")[1].split(";")[0].trim());
            }

            if (StrUtil.containsIgnoreCase(syslog, "ip-proto-id")) {
                obj.put("protoid", syslog.split("ip-proto-id")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "source-ip")) {
                obj.put("source-ip", syslog.split("source-ip")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "source-port")) {
                obj.put("source_port", syslog.split("source-port")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "destination-ip")) {
                obj.put("destination_ip", syslog.split("destination-ip")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "destination-port")) {
                obj.put("destination_port", syslog.split("destination-port")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "block-reason")) {
                obj.put("reason", syslog.split("block-reason")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "ifname-inside")) {
                obj.put("in_ifname", syslog.split("ifname-inside")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "ifname-outside")) {
                obj.put("out_ifname", syslog.split("ifname-outside")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "summary-count")) {
                obj.put("summary_count", syslog.split("summary-count")[1].split(":")[1].split(";")[0].trim());
            }
            if (StrUtil.containsIgnoreCase(syslog, "summary-offset")) {
                obj.put("summary_offset", syslog.split("summary-offset")[1].split(":")[1].split(";")[0].trim());
            }
            obj.put("message_content", syslog.split(";")[4].trim());
        }
    }

    private static void syslogParse2(String syslog, JSONObject obj) {
        obj.put("priority", syslog.split(">")[0].split("<")[1]);

        obj.put("event_time", syslog.split(">")[1].split(" ")[0] + " " + syslog.split(">")[1].split(" ")[1]);

        obj.put("hostname", syslog.split(">")[1].split(" ")[2]);

        obj.put("device_uuid", syslog.split("\\%\\%\\-\\-")[1].split("\\/")[0]);

        obj.put("log_type", syslog.split("\\%\\%\\-\\-")[1].split("\\/")[1]);

        obj.put("severity", syslog.split("\\%\\%\\-\\-")[1].split("\\/")[2]);

        obj.put("event_level", syslog.split("\\%\\%\\-\\-")[1].split("\\/")[2]);
    }

    public static void main(String[] args) {
//        String body = "<142> 1 10.28.6.17 1970 Jan 01 08:39:06 FW 123 POLICY: Allow  6|1:0:0:0:0:0:0:128|1024|2:0:0:0:0:0:0:1|80|gige0_1|gige0_2";
//        System.out.println(body.contains("|"));
//        System.out.println(body.split("\\|").length);
//        JSONObject syslog = JSONUtil.createObj().put("syslog", body);
//        Object parse = BastionHost.parse(syslog.toString());
//        System.out.println(parse);
//        String ss = "<142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT444:SessionW 19700101081609";
//        String[] header = ss.split(" ");
//        System.out.println(DateUtil.parse(header[header.length - 1]));


        String body = "<14>2019-09-19 15:42:18 DPTECH %%--DPX/WEB/6/OPERLOG(l): client-type(84):web;user-name(85):admin;host-ip(86):2.74.24.29;error-code(87):0;设置操作日志配置，开启发送到远程IPV4日志主机服务，远程日志主机地址：[2.74.24.29]，本机地址：[100.73.26.149]， 端口：[5141]。 result: Success.";
//        System.out.println(body.split(" ")[5].trim());
        body = "Jul  5 13:26:44 2009 DPTECH %%UAG/ATTACK/0/DATALOG(l): log-type(1):attack-protect;event(2):block;attack-name(11):(352325536)死亡之Ping;protocol-name(17):(50333952)IP;ip-proto-id(18):1;source-ip(24):192.168.1.154;source-port(25):0;destination-ip(26):192.168.1.254;destination-port(27):0;block-reason(28):ABNORMITY-DETECTION;ifname-inside(29):eth0/2;ifname-outside(30):eth0/2;summary-count(33):1;summary-offset(34):0;\n";
//        System.out.println(body.split("\\%\\%")[1].split("\\/")[0]);
//        System.out.println(body.split("\\%\\%")[1].split("\\/")[1]);
//        System.out.println(body.split("\\%\\%")[1].split("\\/")[2]);
//        System.out.println(body.split("log-type")[1].split("\\:")[1].split(";")[0].trim());
        //System.out.println(body.split(";")[4].trim());
        JSONObject obj = new JSONObject();
        syslogParse1(body, obj);
//        System.out.println(obj.toJSONString(2));

        String sys = "<2>2019-09-23 14:58:01 DPTECH %%--DPX/SHRP/2/SYSLOG(l): SHRP status is changed to master from backup because of currnet priority is 110 but neighbor priority is 105!";
        JSONObject obj1 = JSONUtil.createObj();
        obj1.put("syslog", sys);
        System.out.println(JSONUtil.parseObj(parse(obj1.toString())).toJSONString(2));
    }
}