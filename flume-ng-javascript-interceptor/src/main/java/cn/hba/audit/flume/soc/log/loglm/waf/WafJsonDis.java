package cn.hba.audit.flume.soc.log.loglm.waf;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.json.JSONObject;

/**
 * json 内容统一转换
 *
 * @author wbw
 * @date 2019/9/11 17:30
 */
class WafJsonDis {

    static void jsonDis(JSONObject jsonObject, JSONObject obj) {
        disLogMsg1(jsonObject, obj);
        if (jsonObject.containsKey("dst_ip")) {
            obj.put("destination_ip", jsonObject.getStr("dst_ip"));
        }
        if (jsonObject.containsKey("dst_port")) {
            obj.put("destination_port", jsonObject.getStr("dst_port"));
        }
        if (jsonObject.containsKey("url")) {
            obj.put("url", jsonObject.getStr("url"));
        } else if (jsonObject.containsKey("uri")) {
            obj.put("url", jsonObject.getStr("uri"));
        }
        if (jsonObject.containsKey("agent")) {
            obj.put("agent", jsonObject.getStr("agent"));
        }
        if (jsonObject.containsKey("http_protocol")) {
            obj.put("http_protocol", jsonObject.getStr("http_protocol"));
        }
        disLogMsg2(jsonObject, obj);
        if (jsonObject.containsKey("waf_status_code")) {
            obj.put("waf_status_code", jsonObject.getInt("waf_status_code"));
        }
        if (jsonObject.containsKey("ser_status_code")) {
            obj.put("ser_status_code", jsonObject.getInt("ser_status_code"));
        }
        if (jsonObject.containsKey("correlation_id")) {
            obj.put("correlation_id", jsonObject.getStr("correlation_id"));
        }
        if (jsonObject.containsKey("event_type")) {
            obj.put("desc", jsonObject.getStr("event_type"));
        }
        if (jsonObject.containsKey("policy_desc")) {
            obj.put("interface_name", jsonObject.getStr("policy_desc"));
        }

        disLogMsg3(jsonObject, obj);
        disLogMsg4(jsonObject, obj);
        disLogMsg5(jsonObject, obj);
    }

    private static void disLogMsg5(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("source")) {
            switch (jsonObject.getStr("source").trim()) {
                case "interface":
                    obj.put("data_source", "Web界面");
                    break;
                case "system":
                    obj.put("data_source", "Daemon/脚本");
                    break;
                case "engine":
                    obj.put("data_source", "WAF引擎");
                    break;
                default:
                    obj.put("data_source", "系统监控");
            }
        }
        if (jsonObject.containsKey("type")) {
            switch (jsonObject.getStr("type").trim().toLowerCase()) {
                case "system":
                    obj.put("opt_type", "开关电源");
                    break;
                case "pm":
                    obj.put("opt_type", "服务启停");
                    break;
                case "engine":
                    obj.put("opt_type", "引擎启停");
                    break;
                case "database":
                    obj.put("opt_type", "数据库启停");
                    break;
                case "web":
                    obj.put("opt_type", "Web服务启停");
                    break;
                case "link":
                    obj.put("opt_type", "以太网口启停");
                    break;
                case "emergency":
                    obj.put("opt_type", "WAF紧急模式");
                    break;
                case "ads":
                    obj.put("opt_type", "ADS联动");
                    break;
                case "dev_resource":
                    obj.put("opt_type", "设备资源情况");
                    break;
                default:
                    obj.put("opt_type", "规则升级");
            }
        }
    }

    private static void disLogMsg4(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("action")) {
            if (NumberUtil.isNumber(jsonObject.getStr("action"))) {
                switch (NumberUtil.parseInt(jsonObject.getStr("action"))) {
                    case 1:
                        obj.put("action", "转发 - 对于符合条件的请求，WAF直接转发给目的服务器，不再做进一步的安全检查。");
                        break;
                    case 2:
                        obj.put("action", "阻断 - 对于符合条件的请求，WAF结束当前策略检查，并断开当前TCP连接（这种情况下，WAF提供源IP阻断功能）。");
                        break;
                    case 3:
                        obj.put("action", "接受 - 对于符合条件的请求，WAF结束当前策略检查，但会继续进行其他的安全检查。");
                        break;
                    default:
                        obj.put("action", "重定向 - 对于符合条件的请求，WAF构造302重定向消息回复给客户端，并且断开TCP连接。");
                }
            } else {
                switch (jsonObject.getStr("action").trim().toLowerCase()) {
                    case "other":
                        obj.put("action", "放过");
                        break;
                    case "forward":
                        obj.put("action", "放过");
                        break;
                    case "block":
                        obj.put("action", "阻断 - 对于符合条件的请求，WAF结束当前策略检查，并断开当前TCP连接（这种情况下，WAF提供源IP阻断功能）。");
                        break;
                    case "accept":
                        obj.put("action", "接受 - 对于符合条件的请求，WAF结束当前策略检查，但会继续进行其他的安全检查。");
                        break;
                    case "redirect":
                        obj.put("action", "重定向 - 对于符合条件的请求，WAF构造302重定向消息回复给客户端，并且断开TCP连接。");
                        break;
                    case "pretend":
                        obj.put("action", "伪装 - 对于符合条件的请求，WAF自定义HTTP响应码回复给客户端，并断开当前TCP连接");
                        break;
                    case "set":
                        obj.put("action", "设定");
                        break;
                    case "clear":
                        obj.put("action", "清除");
                        break;
                    case "replace":
                        obj.put("action", "替换");
                        break;
                    default:
                        obj.put("action", jsonObject.getStr("action").trim());
                }
            }
        }
        disLogMethod(jsonObject, obj);
    }

    private static void disLogMethod(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("method")) {
            if (NumberUtil.isNumber(jsonObject.getStr("method"))) {
                // 2的倍数
                switch (jsonObject.getInt("method")) {
                    case 1:
                        obj.put("method", "UNKNOWN");
                        break;
                    case 2:
                        obj.put("method", "GET");
                        break;
                    case 4:
                        obj.put("method", "HEAD");
                        break;
                    case 8:
                        obj.put("method", "POST");
                        break;
                    case 16:
                        obj.put("method", "PUT");
                        break;
                    case 32:
                        obj.put("method", "DELETE");
                        break;
                    case 64:
                        obj.put("method", "MKCOL");
                        break;
                    case 128:
                        obj.put("method", "COPY");
                        break;
                    case 256:
                        obj.put("method", "MOVE");
                        break;
                    case 512:
                        obj.put("method", "OPTIONS");
                        break;
                    case 1024:
                        obj.put("method", "PROPFIND");
                        break;
                    case 2048:
                        obj.put("method", "PROPPATCH");
                        break;
                    case 4096:
                        obj.put("method", "LOCK");
                        break;
                    case 8192:
                        obj.put("method", "UNLOCK");
                        break;
                    case 16384:
                        obj.put("method", "TRACE");
                        break;
                    case 65536:
                        obj.put("method", "CONNECT");
                        break;
                    case 131072:
                        obj.put("method", "PATCH");
                        break;
                    case 262144:
                        obj.put("method", "VERSION_CONTROL");
                        break;
                    case 524288:
                        obj.put("method", "CHECKOUT");
                        break;
                    case 1048576:
                        obj.put("method", "UNCHECKOUT");
                        break;
                    case 2097152:
                        obj.put("method", "CHECKIN");
                        break;
                    case 4194304:
                        obj.put("method", "UPDATE");
                        break;
                    case 8388608:
                        obj.put("method", "LABEL");
                        break;
                    case 16777216:
                        obj.put("method", "REPORT");
                        break;
                    case 33554432:
                        obj.put("method", "MKWORKSPACE");
                        break;
                    case 67108864:
                        obj.put("method", "MKACTIVITY");
                        break;
                    case 134217728:
                        obj.put("method", "BASELINE_CONTROL");
                        break;
                    case 268435456:
                        obj.put("method", "MERGE");
                        break;
                    default:
                        // 32768
                        obj.put("method", "SEARCH");
                }
            } else {
                obj.put("method", jsonObject.getStr("method"));
            }
        }
    }

    private static void disLogMsg3(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("wa_host")) {
            obj.put("wa_host", jsonObject.getStr("wa_host"));
        }
        if (jsonObject.containsKey("wa_referer")) {
            obj.put("wa_referer", jsonObject.getStr("wa_referer"));
        }
        if (jsonObject.containsKey("cpu")) {
            obj.put("cpu_mes", jsonObject.getInt("cpu"));
        }
        if (jsonObject.containsKey("mem")) {
            obj.put("mem_mes", jsonObject.getInt("mem"));
        }
        if (jsonObject.containsKey("domain")) {
            obj.put("domain", jsonObject.getStr("domain"));
        }
        if (jsonObject.containsKey("policy_id")) {
            obj.put("policy_id", jsonObject.getStr("policy_id"));
        }
        if (jsonObject.containsKey("rule_id")) {
            obj.put("rule_id", jsonObject.getStr("rule_id"));
        }
        if (jsonObject.containsKey("block")) {
            obj.put("ip_block", jsonObject.getStr("block"));
        }
        if (jsonObject.containsKey("block_info")) {
            obj.put("block_info", jsonObject.getStr("block_info"));
        }
        if (jsonObject.containsKey("http")) {
            obj.put("http", jsonObject.getStr("http"));
        }
        if (jsonObject.containsKey("alertinfo")) {
            obj.put("alert_info", jsonObject.getStr("alertinfo"));
        }
        if (jsonObject.containsKey("proxy_info")) {
            obj.put("proxy_info", jsonObject.getStr("proxy_info"));
        }
        if (jsonObject.containsKey("charaters")) {
            obj.put("attack_times", jsonObject.getStr("charaters"));
        }
        if (jsonObject.containsKey("count_num")) {
            obj.put("count_num", jsonObject.getInt("count_num"));
        }
        if (jsonObject.containsKey("protocol_type")) {
            obj.put("protocol_type", jsonObject.getStr("protocol_type"));
        }
        if (jsonObject.containsKey("site_name")) {
            obj.put("site_name", jsonObject.getStr("site_name"));
        }
        if (jsonObject.containsKey("vsite_name")) {
            obj.put("vsite_name", jsonObject.getStr("vsite_name"));
        }
        if (jsonObject.containsKey("src_mac")) {
            obj.put("source_mac", jsonObject.getStr("src_mac"));
        }
        if (jsonObject.containsKey("attack_type")) {
            obj.put("attack_type", jsonObject.getStr("attack_type"));
        }
        if (jsonObject.containsKey("dst_mac")) {
            obj.put("destination_mac", jsonObject.getStr("dst_mac"));
        }

        if (jsonObject.containsKey("def_ip")) {
            obj.put("def_ip", jsonObject.getStr("def_ip"));
        }
        if (jsonObject.containsKey("def_mac")) {
            obj.put("def_mac", jsonObject.getStr("def_mac"));
        }
        if (jsonObject.containsKey("conflit_mac")) {
            obj.put("conflit_mac", jsonObject.getStr("conflit_mac"));
        }
        if (jsonObject.containsKey("status")) {
            if (NumberUtil.isNumber(jsonObject.getStr("status"))) {
                obj.put("status", NumberUtil.parseInt(jsonObject.getStr("status")) == 0 ? "尝试发起攻击" : "攻击成功");
            } else {
                obj.put("status", jsonObject.getStr("status"));
            }
        }
    }

    private static void disLogMsg2(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("protocol_type")) {
            obj.put("protocol_type", jsonObject.getStr("protocol_type"));
        } else if (jsonObject.containsKey("protocol")) {
            if (NumberUtil.isNumber(jsonObject.getStr("protocol"))) {
                switch (jsonObject.getInt("protocol")) {
                    case 0:
                        obj.put("protocol_type", "所有协议");
                        break;
                    case 1:
                        obj.put("protocol_type", "ICMP");
                        break;
                    case 6:
                        obj.put("protocol_type", "TCP");
                        break;
                    case 17:
                        obj.put("protocol_type", "UDP");
                        break;
                    default:
                        obj.put("protocol_type", jsonObject.getStr("protocol"));
                }
            } else {
                obj.put("protocol_type", jsonObject.getStr("protocol"));
            }
        }


        if (jsonObject.containsKey("alertlevel")) {
            switch (jsonObject.getStr("alertlevel").trim().toLowerCase()) {
                case "high":
                    obj.put("alarm_level", "高");
                    break;
                case "medium":
                    obj.put("alarm_level", "中");
                    break;
                case "low":
                    obj.put("alarm_level", "低");
                    break;
                default:
                    obj.put("alarm_level", jsonObject.getStr("alertlevel"));
            }
        }
        if (jsonObject.containsKey("wsi")) {
            obj.put("wsi", jsonObject.getStr("wsi"));
        }
        if (jsonObject.containsKey("wci")) {
            obj.put("wci", jsonObject.getStr("wci"));
        }
        if (jsonObject.containsKey("country")) {
            obj.put("ip_country", jsonObject.getStr("country"));
        }
        if (jsonObject.containsKey("req_content_type")) {
            obj.put("req_content_type", jsonObject.getStr("req_content_type"));
        }
        if (jsonObject.containsKey("req_content_len")) {
            obj.put("req_content_len", jsonObject.getInt("req_content_len"));
        }
        if (jsonObject.containsKey("res_content_type")) {
            obj.put("res_content_type", jsonObject.getStr("res_content_type"));
        }
        if (jsonObject.containsKey("res_content_len")) {
            obj.put("res_content_len", jsonObject.getStr("res_content_len"));
        }
    }

    private static void disLogMsg1(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("reason")) {
            if (NumberUtil.isNumber(jsonObject.getStr("reason"))) {
                switch (NumberUtil.parseInt(jsonObject.getStr("reason"))) {
                    case 1:
                        obj.put("reason", "包含不安全内容");
                        break;
                    case 2:
                        obj.put("reason", "非法改变原始内容");
                        break;
                    case 3:
                        obj.put("reason", "非法删除原始内容");
                        break;
                    default:
                        obj.put("reason", "未知");

                }
            } else {
                obj.put("reason", jsonObject.getStr("reason"));
            }
        }
        if (jsonObject.containsKey("src_port")) {
            obj.put("source_port", jsonObject.getStr("src_port"));
        }
        if (jsonObject.containsKey("password")) {
            obj.put("user_pwd", jsonObject.getStr("password"));
        }
        if (jsonObject.containsKey("src_ip")) {
            obj.put("source_ip", jsonObject.getStr("src_ip"));
        }
        if (jsonObject.containsKey("result")) {
            obj.put("result", jsonObject.getStr("result"));
        }
        if (jsonObject.containsKey("session_id")) {
            obj.put("session_id", jsonObject.getStr("session_id"));
        }
        if (jsonObject.containsKey("op_type")) {
            obj.put("opt_type", jsonObject.getStr("op_type"));
        }
        if (jsonObject.containsKey("stat_time")) {
            obj.put("start_time", jsonObject.getStr("stat_time"));
        }
        if (jsonObject.containsKey("user")) {
            obj.put("user_name", jsonObject.getStr("user"));
        }
        if (jsonObject.containsKey("desc")) {
            obj.put("message_content", jsonObject.getStr("desc"));
        }
        if (jsonObject.containsKey("info")) {
            obj.put("message_content", jsonObject.getStr("info"));
        }
        if (jsonObject.containsKey("site_id")) {
            obj.put("site_id", jsonObject.getStr("site_id"));
        }
        if (jsonObject.containsKey("protect_id")) {
            obj.put("protect_id", jsonObject.getStr("protect_id"));
        }
    }
}
