package cn.hba.audit.flume.soc.log.logwyxy;

import cn.hutool.json.JSONObject;

/**
 * 网御星云 防火墙
 *
 * @author wbw
 * @date 2019/9/18 8:53
 */
class WyxyJsonDis {

    static void dis(JSONObject object, JSONObject obj) {
        Integer devid = object.getInt("devid");
        switch (devid) {
            case 0:
                obj.put("device_uuid", "Firewall");
                break;
            case 1:
                obj.put("device_uuid", "IDS");
                break;
            case 2:
                obj.put("device_uuid", "VPN");
                break;
            case 3:
                obj.put("device_uuid", "utm");
                break;
            default:
                obj.put("device_uuid", devid);
        }

        obj.put("start_time", object.getStr("date"));
        obj.put("hostname", object.getStr("dname"));
        obj.put("event_type", object.getStr("mod"));
        obj.put("event_level", object.getInt("pri", 7));
        obj.put("device_version", object.getStr("ver"));
        Integer logtype = object.getInt("logtype");
        disLogLogType(obj, logtype);

        disLogMsg1(object, obj);
//interface	接口
        if (object.containsKey("interface")) {
            obj.put("interface_name", object.getStr("interface"));
        }
        disLogMsg2(object, obj);
//dstip	目的地IP地址
        if (object.containsKey("dstip")) {
            obj.put("destination_ip", object.getStr("dstip"));
        }
        //dip	目的地IP地址
        else if (object.containsKey("dip")) {
            obj.put("destination_ip", object.getStr("dip"));
        }
        disLogMsg3(object, obj);
//sender	发送邮箱
        if (object.containsKey("sender")) {
            obj.put("sender", object.getStr("sender"));
        }
        disLogMsg4(object, obj);

        //repeated	重复次数
        if (object.containsKey("repeated")) {
            obj.put("repeated", object.getStr("repeated"));
        }
        disLogMsg5(object, obj);


        //iif	输入接口
        if (object.containsKey("iif")) {
            obj.put("in_ifname", object.getStr("iif"));
        }
        disLogMsg6(object, obj);
    }

    private static void disLogMsg6(JSONObject object, JSONObject obj) {
        //ip	IP地址

        if (object.containsKey("ip")) {
            obj.put("source_ip", object.getStr("ip"));
        }
        //id	序列号
        if (object.containsKey("id")) {
            obj.put("sn", object.getStr("id"));
        }

        //page	页面
        if (object.containsKey("page")) {
            obj.put("url", object.getStr("page"));
        }
        //from	主机
        if (object.containsKey("from")) {
            obj.put("hostname", object.getStr("from"));
        }
        //agent	代理
        if (object.containsKey("agent")) {
            obj.put("agent", object.getStr("agent"));
        }
        //information	信息
        if (object.containsKey("information")) {
            obj.put("message_content", object.getStr("information"));
        }
        //file	文件
        if (object.containsKey("file")) {
            obj.put("source_file", object.getStr("file"));
        }
        //proto	协议
        if (object.containsKey("proto")) {
            obj.put("destination_protocol", object.getStr("proto"));
        } else if (object.containsKey("protocol")) {
            //protocol	协议
            obj.put("destination_protocol", object.getStr("protocol"));
        }
        //now_err_num	当前错误次数
        if (object.containsKey("now_err_num")) {
            obj.put("count_num", object.getInt("now_err_num"));
        } else if (object.containsKey("max_err_num")) {
            //max_err_num	允许最大错误次数
            obj.put("count_num", object.getInt("max_err_num"));
        }
        disLogMsg7(object, obj);

    }

    private static void disLogMsg7(JSONObject object, JSONObject obj) {
        //password	密码
        if (object.containsKey("password")) {
            obj.put("user_pwd", object.getStr("password"));
        }
        //powername	权限名称
        if (object.containsKey("powername")) {
            obj.put("powername", object.getStr("powername"));
        }
        //urlblock	URL过滤策略
        if (object.containsKey("urlblock")) {
            obj.put("profile", object.getStr("urlblock"));
        }
        //username	用户名称
        if (object.containsKey("username")) {
            obj.put("user_name", object.getStr("username"));
        } else if (object.containsKey("user")) {
            //user	用户
            obj.put("user_name", object.getStr("user"));
        }

        //type	类型
        if (object.containsKey("type")) {
            obj.put("application_category", object.getStr("type"));
        }
        //time	时间
        if (object.containsKey("time")) {
            obj.put("start_time", object.getStr("time"));
        }
        //cacert                              	CA证书
        if (object.containsKey("cacert")) {
            obj.put("cacert", object.getStr("cacert"));
        }
        //fwcert          	 安全网关证书
        if (object.containsKey("fwcert")) {
            obj.put("fwcert", object.getStr("fwcert"));
        }
        //fwkey                               	安全网关密钥
        if (object.containsKey("fwkey")) {
            obj.put("fwkey", object.getStr("fwkey"));
        }
        //admincert                           	管理员证书
        if (object.containsKey("admincert")) {
            obj.put("leftcert", object.getStr("admincert"));
        }
        //ipv6                                 	IPv6地址
        if (object.containsKey("ipv6")) {
            obj.put("def_ip", object.getStr("ipv6"));
        }
        //client	客户端
        if (object.containsKey("client")) {
            obj.put("client", object.getStr("client"));
        }
        //Request	请求连接
        if (object.containsKey("Request")) {
            obj.put("request", object.getStr("Request"));
        }
        //Disconnect	断开连接
        if (object.containsKey("Disconnect")) {
            obj.put("disconnect", object.getStr("Disconnect"));
        }
    }

    private static void disLogMsg5(JSONObject object, JSONObject obj) {
        //proxy	代理
        if (object.containsKey("proxy")) {
            obj.put("agent", object.getStr("proxy"));
        }
        //ps	公开服务
        if (object.containsKey("proxy")) {
            obj.put("agent", object.getStr("proxy"));
        }
        //pa	公开地址
        if (object.containsKey("proxy")) {
            obj.put("agent", object.getStr("proxy"));
        }
        //policy	策略
        if (object.containsKey("ruleid")) {
            obj.put("ruleid", object.getStr("ruleid"));
        }
        //port	端口号
        if (object.containsKey("port")) {
            obj.put("source_port", object.getStr("port"));
        }
        //long	长连接
        if (object.containsKey("long")) {
            obj.put("connid", object.getStr("long"));
        }
        //priority	有限级
        if (object.containsKey("priority")) {
            obj.put("priority", object.getStr("priority"));
            //prio	优先级
        } else if (object.containsKey("prio")) {
            obj.put("priority", object.getStr("prio"));
        }

        //oif	输出接口
        if (object.containsKey("oif")) {
            obj.put("oif", object.getStr("oif"));
        }
        //newid	新ID序列号
        if (object.containsKey("newid")) {
            obj.put("sn", object.getStr("newid"));
        }
        //name	名称.
        if (object.containsKey("name")) {
            obj.put("admin_name", object.getStr("name"));
        }
        //mh_flag	移动扩展头
        if (object.containsKey("mh_flag")) {
            obj.put("mh_flag", object.getStr("mh_flag"));
        }
        //metric	路由权重
        if (object.containsKey("metric")) {
            obj.put("metric", object.getStr("metric"));
        }
        //msg	信息
        if (object.containsKey("msg")) {
            obj.put("message_content", object.getStr("msg"));
        }
        //log	日志
        if (object.containsKey("msg")) {
            obj.put("fwlog", object.getStr("msg"));
        }
        //language	语言
        if (object.containsKey("language")) {
            obj.put("language", object.getStr("language"));
        }
        //is	内部服务
        if (object.containsKey("is")) {
            obj.put("is", object.getStr("is"));
        }
        //iport	端口
        if (object.containsKey("source_port")) {
            obj.put("source_port", object.getStr("source_port"));
        }
        //iat	内部地址
        if (object.containsKey("iat")) {
            obj.put("iat", object.getStr("iat"));
            //ia	内部地址
        } else if (object.containsKey("ia")) {
            obj.put("iat", object.getStr("ia"));
        }
    }

    private static void disLogMsg4(JSONObject object, JSONObject obj) {
        //srcport	源端口
        if (object.containsKey("srcport")) {
            obj.put("source_port", object.getStr("srcport"));
            //saport	源端口
        } else if (object.containsKey("saport")) {
            obj.put("source_port", object.getStr("saport"));
            //sport	源端口
        } else if (object.containsKey("sport")) {
            obj.put("source_port", object.getStr("sport"));
        }


        //satport	源转换端口
        if (object.containsKey("satport")) {
            obj.put("original_source_port", object.getStr("satport"));
        }

        //severity	安全级别
        if (object.containsKey("severity")) {
            obj.put("severity", object.getStr("severity"));
        }
        //smac	源MAC地址
        if (object.containsKey("smac")) {
            obj.put("source_mac", object.getStr("smac"));
        }

        //sata	源地址转换
        if (object.containsKey("sata")) {
            obj.put("original_source_ip", object.getStr("sata"));
            //sat	源地址转换
        } else if (object.containsKey("sat")) {
            obj.put("original_source_ip", object.getStr("sat"));
        }

        //service	服务
        if (object.containsKey("service")) {
            obj.put("service", object.getStr("service"));
        }
        //sa	源地址
        if (object.containsKey("sa")) {
            obj.put("source_address", object.getStr("sa"));
            //srcaddr	源地址
        } else if (object.containsKey("srcaddr")) {
            obj.put("source_address", object.getStr("srcaddr"));
        }


        //srcip	源IP地址
        if (object.containsKey("srcip")) {
            obj.put("source_ip", object.getStr("srcip"));
            //sip	源IP地址
        } else if (object.containsKey("sip")) {
            obj.put("source_ip", object.getStr("sip"));
        }

        //serviceid	服务序列号
        if (object.containsKey("serviceid")) {
            obj.put("service_id", object.getStr("serviceid"));
        }
        //servicename	服务名称
        if (object.containsKey("servicename")) {
            obj.put("service_name", object.getStr("servicename"));
        }
        //rt_flag	选路扩展头
        if (object.containsKey("rt_flag")) {
            obj.put("rt_flag", object.getStr("rt_flag"));
        }
        //result	结果
        if (object.containsKey("result")) {
            obj.put("result", object.getStr("result"));
        }
    }

    private static void disLogMsg3(JSONObject object, JSONObject obj) {
        //duration	周期
        if (object.containsKey("duration")) {
            obj.put("duration_time", object.getStr("duration"));
        }
//domain	域名
        if (object.containsKey("domain")) {
            obj.put("domain", object.getStr("domain"));
        }

//eventtype	事件类型
        if (object.containsKey("eventtype")) {
            obj.put("opt_subtype", object.getStr("eventtype"));
        }
//eventname	事件名
        if (object.containsKey("eventname")) {
            obj.put("event_name", object.getStr("eventname"));
        }
//eventdetails	事件详情
        if (object.containsKey("eventdetails")) {
            obj.put("event_details", object.getStr("eventdetails"));
        }
//esp_flag	加密扩展头
        if (object.containsKey("esp_flag")) {
            obj.put("esp_flag", object.getStr("esp_flag"));
        }
//export	导出
        if (object.containsKey("export")) {
            obj.put("export", object.getStr("export"));
        }

//import	导入
        if (object.containsKey("import")) {
            obj.put("import", object.getStr("import"));
        }

        //if	链路别名
        if (object.containsKey("if")) {
            obj.put("if", object.getStr("if"));
        }
        //table	表名
        if (object.containsKey("table")) {
            obj.put("table", object.getStr("table"));
        }
        //tablename	表名称
        if (object.containsKey("tablename")) {
            obj.put("table_name", object.getStr("tablename"));
        }
        //smtpport	smtp服务器端口
        if (object.containsKey("smtpport")) {
            obj.put("smtp_port", object.getStr("smtpport"));
        }  //smtp	smtp服务器
        else if (object.containsKey("smtp")) {
            obj.put("smtp_port", object.getStr("smtp"));
        }
        //log_power	日志邮件报警
        if (object.containsKey("log_power")) {
            obj.put("log_power", object.getStr("log_power"));
        }

        //receiver	接收邮箱
        if (object.containsKey("receiver")) {
            obj.put("recipient", object.getStr("receiver"));
        }
        //rcvd	已接收
        if (object.containsKey("rcvd")) {
            obj.put("rcvd", object.getStr("rcvd"));
        }
        //sent	已发送
        if (object.containsKey("sent")) {
            obj.put("sent", object.getStr("sent"));
        }
    }

    private static void disLogMsg2(JSONObject object, JSONObject obj) {
        //hbh_flag	逐跳扩展头
        if (object.containsKey("hbh_flag")) {
            obj.put("hbh_flag", object.getStr("hbh_flag"));
        }
//gateway	网关
        if (object.containsKey("gateway")) {
            obj.put("vpn_name", object.getStr("gateway"));
        }
//frag_flag	分段扩展头
        if (object.containsKey("frag_flag")) {
            obj.put("frag_flag", object.getStr("frag_flag"));
        }
//dcfpolicy	深度过滤策略
        if (object.containsKey("dcfpolicy")) {
            obj.put("dcfpolicy", object.getStr("dcfpolicy"));
        }//dcf	深度过滤
        else if (object.containsKey("dcf")) {
            obj.put("dcfpolicy", object.getStr("dcf"));
        }

//da	目的地址
        if (object.containsKey("da")) {
            obj.put("destination_address", object.getStr("da"));
        }
//destaddr	目的地址
        else if (object.containsKey("destaddr")) {
            obj.put("destination_address", object.getStr("destaddr"));
        }
//destport	目的端口
        if (object.containsKey("destport")) {
            obj.put("destination_port", object.getStr("destport"));
        } //dstport	目的端口
        else if (object.containsKey("dstport")) {
            obj.put("destination_port", object.getStr("dstport"));
        }
        //dport	目的端口
        else if (object.containsKey("dport")) {
            obj.put("destination_port", object.getStr("dport"));
        }
//dst_flag	目的地扩展头
        if (object.containsKey("dst_flag")) {
            obj.put("destination_flag", object.getStr("dst_flag"));
        }
    }

    private static void disLogMsg1(JSONObject object, JSONObject obj) {
        if (object.containsKey("act")) {
            obj.put("opt_type", object.getStr("act"));
        }
        if (object.containsKey("dsp_msg")) {
            obj.put("message_content", object.getStr("dsp_msg"));
        }
        if (object.containsKey("result")) {
            obj.put("result", object.getStr("result"));
        }
        if (object.containsKey("cmd")) {
            obj.put("cmd", object.getStr("cmd"));
        }
        if (object.containsKey("user")) {
            obj.put("user_name", object.getStr("user"));
        }
        if (object.containsKey("action")) {
            obj.put("action", object.getStr("action"));
        }
        if (object.containsKey("comment")) {
            obj.put("comment", object.getStr("comment"));
        }
        if (object.containsKey("apc")) {
            obj.put("ruleid", object.getStr("apc"));
        }


//        ah_flag	验证扩展头
        if (object.containsKey("ah_flag")) {
            obj.put("ah_flag", object.getStr("ah_flag"));
        }
//active	状态
        if (object.containsKey("active")) {
            obj.put("status", object.getStr("active"));
        } //status	状态
        else if (object.containsKey("status")) {
            obj.put("status", object.getStr("status"));
        }//code	状态值
        else if (object.containsKey("code")) {
            obj.put("status", object.getStr("code"));
        }
//admin	管理者
        if (object.containsKey("admin")) {
            obj.put("admin_name", object.getStr("admin"));
        }
    }

    private static void disLogLogType(JSONObject obj, Integer logtype) {
        switch (logtype) {
            case 1:
                obj.put("log_des", "网御星云 - 防火墙 - 包过滤（包括：包过滤、NAT、端口映射、IP映射、IDS阻断等）");
                break;
            case 2:
                obj.put("log_des", "网御星云 - 防火墙 - 应用代理、SOCKS代理");
                break;
            case 3:
                obj.put("log_des", "网御星云 - 防火墙 - 联动日志(1、对应强五的入侵检测日志，包含：内嵌的IDS（暂无）、联动的IDS、防火墙内部的抗攻击信息\n" +
                        "2、将与ISM的联动日志也添加到了此类别中来。)");
                break;
            case 4:
                obj.put("log_des", "网御星云 - 防火墙 - Vpn模块相关日志");
                break;
            case 5:
                obj.put("log_des", "网御星云 - 防火墙 - 用户认证相关日志");
                break;
            case 6:
                obj.put("log_des", "网御星云 - 防火墙 - 内容过滤日志(HTTP(URL过滤 / 内容过滤)\n" +
                        "FTP过滤日志(FTP命令过滤、FTP内容过滤)\n" +
                        "邮件过滤日志(SMTP、POP3内容过滤：收发信人地址、邮件主题过滤、邮件内容或附件内容过滤))");
                break;
            case 7:
                obj.put("log_des", "网御星云 - 防火墙 - 病毒防护日志");
                break;
            case 8:
                obj.put("log_des", "网御星云 - 防火墙 - 设备状态日志");
                break;
            case 9:
                obj.put("log_des", "网御星云 - 防火墙 - 设备管理日志 ");
                break;
            case 10:
                obj.put("log_des", "网御星云 - 防火墙 - HA日志 ");
                break;
            case 11:
                obj.put("log_des", "网御星云 - 防火墙 - 可扩展 ");
                break;
            case 12:
                obj.put("log_des", "网御星云 - 防火墙 - 反垃圾邮件代理日志 ");
                break;
            case 13:
                obj.put("log_des", "网御星云 - 防火墙 - URL过滤日志 ");
                break;
            case 14:
                obj.put("log_des", "网御星云 - 防火墙 - 病毒隔离日志 ");
                break;
            case 15:
                obj.put("log_des", "网御星云 - 防火墙 - 主机隔离日志 ");
                break;
            case 16:
                obj.put("log_des", "网御星云 - 防火墙 - 入侵防御日志 ");
                break;
            default:
                obj.put("log_des", "网御星云 - 防火墙 - " + logtype);
        }
    }
}
