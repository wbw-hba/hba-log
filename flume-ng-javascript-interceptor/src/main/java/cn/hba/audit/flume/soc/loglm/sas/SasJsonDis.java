package cn.hba.audit.flume.soc.loglm.sas;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;

/**
 * sas 通用字段解析
 *
 * @author wbw
 * @date 2019/9/16 9:52
 */
class SasJsonDis {

    static void dispose(JSONObject log, JSONObject obj) {
        disLogMsg1(log, obj);

        if (log.containsKey("user")) {
            obj.put("user_name", log.getStr("user"));
        }

        if (log.containsKey("ruleid")) {
            obj.put("rule_id", log.getStr("ruleid"));
        } else if (log.containsKey("rule_id")) {
            obj.put("rule_id", log.getStr("rule_id"));
        }
        if (log.containsKey("scmid")) {
            obj.put("scmid", log.getStr("scmid"));
        }
        if (log.containsKey("scmname")) {
            obj.put("scmname", log.getStr("scmname"));
        }


        if (log.containsKey("alerted")) {
            obj.put("alerted", log.getStr("alerted"));
        }
        if (log.containsKey("dropped")) {
            obj.put("dropped", log.getStr("dropped"));
        }
        disLogCat(log, obj);


        disLogType(log, obj);

        if (log.containsKey("keyword")) {
            obj.put("keyword", log.getStr("keyword"));
        }
        if (log.containsKey("restore")) {
            obj.put("restore", log.getStr("restore"));
        }

        if (log.containsKey("module")) {
            obj.put("event_type", log.getStr("module"));
        }


        if (log.containsKey("src_card")) {
            obj.put("src_card", log.getStr("src_card"));
        }
        if (log.containsKey("dst_card")) {
            obj.put("dst_card", log.getStr("dst_card"));
        }
        if (log.containsKey("action")) {
            String action = log.getStr("action");
            switch (action.trim().toLowerCase()) {
                case "drop":
                    obj.put("act", "阻断");
                    break;
                case "accept":
                    obj.put("act", "允许");
                    break;
                case "auth":
                    obj.put("act", "认证");
                    break;
                default:
                    obj.put("act", action);
            }
        }
        disLogMsg(log, obj);
        disLogTrackMethod(log, obj);
    }

    private static void disLogMsg1(JSONObject log, JSONObject obj) {
        if (log.containsKey("time")) {
            obj.put("event_time", log.getStr("time"));
        }
        if (log.containsKey("card")) {
            obj.put("card", log.getStr("card"));
        }
        if (log.containsKey("sip")) {
            obj.put("source_ip", log.getStr("sip"));
        } else if (log.containsKey("src_ip")) {
            obj.put("source_ip", log.getStr("src_ip"));
        }
        if (log.containsKey("sport")) {
            obj.put("source_port", log.getStr("sport"));
        } else if (log.containsKey("src_port")) {
            obj.put("source_port", log.getStr("src_port"));
        }
        if (log.containsKey("smac")) {
            obj.put("source_mac", log.getStr("smac"));
        } else if (log.containsKey("src_mac")) {
            obj.put("source_mac", log.getStr("src_mac"));
        }
        if (log.containsKey("dip")) {
            obj.put("destination_ip", log.getStr("dip"));
        } else if (log.containsKey("dst_ip")) {
            obj.put("source_port", log.getStr("dst_ip"));
        }
        if (log.containsKey("dport")) {
            obj.put("destination_port", log.getStr("dport"));
        } else if (log.containsKey("dst_port")) {
            obj.put("source_port", log.getStr("dst_port"));
        }
        if (log.containsKey("dmac")) {
            obj.put("destination_mac", log.getStr("dmac"));
        } else if (log.containsKey("dst_mac")) {
            obj.put("destination_mac", log.getStr("dst_mac"));
        }
    }

    private static void disLogMsg(JSONObject log, JSONObject obj) {
        if (log.containsKey("protocol")) {
            obj.put("app_protocol", log.getStr("protocol"));
        }
        if (log.containsKey("nat_dst_port")) {
            obj.put("nat_dst_port", log.getStr("nat_dst_port"));
        }
        if (log.containsKey("nat_dst_ip")) {
            obj.put("nat_dst_ip", log.getStr("nat_dst_ip"));
        }
        if (log.containsKey("nat_src_port")) {
            obj.put("nat_src_port", log.getStr("nat_src_port"));
        }
        if (log.containsKey("nat_src_ip")) {
            obj.put("nat_src_ip", log.getStr("nat_src_ip"));
        }

        if (log.containsKey("comment")) {
            obj.put("message_content_explain", log.getStr("comment"));
        }
        if (log.containsKey("app_name")) {
            obj.put("application_name", log.getStr("app_name"));
        }

        if (log.containsKey("app_id")) {
            obj.put("application_id", log.getStr("app_id"));
        }
        if (log.containsKey("category")) {
            obj.put("application_category", log.getStr("category"));
        }
        if (log.containsKey("subcategory")) {
            obj.put("application_subcategory", log.getStr("subcategory"));
        }
        disLogRisk(log, obj);
        if (log.containsKey("tags")) {
            obj.put("tags", log.getStr("tags"));
        }
        if (log.containsKey("technology")) {
            obj.put("technology", log.getStr("technology"));
        }
    }

    private static void disLogTrackMethod(JSONObject log, JSONObject obj) {
        if (log.containsKey("track_method")) {
            String trackMethod = log.getStr("track_method");
            switch (trackMethod.toLowerCase().toLowerCase()) {
                case "track_start":
                    obj.put("track_method", "会话开始记录日志");
                    break;
                case "track_end":
                    obj.put("track_method", "会话结束记录日志");
                    break;
                case "track_all":
                    obj.put("track_method", "每个数据包都记录一次日志");
                    break;
                default:
                    obj.put("track_method", trackMethod);
            }
        }
    }

    private static void disLogRisk(JSONObject log, JSONObject obj) {
        if (log.containsKey("risk")) {
            if (NumberUtil.isNumber(log.getStr("risk"))) {
                switch (log.getInt("risk")) {
                    case 1:
                        obj.put("risk_level", "低风险");
                        break;
                    case 2:
                        obj.put("risk_level", "较低风险");
                        break;
                    case 3:
                        obj.put("risk_level", "中风险");
                        break;
                    case 4:
                        obj.put("risk_level", "较高风险");
                        break;
                    case 5:
                        obj.put("risk_level", "高风险");
                        break;
                    default:
                        obj.put("risk_level", "未知");
                }
            } else {
                obj.put("risk_level", log.getStr("risk"));
            }
        }
    }

    private static void disLogType(JSONObject log, JSONObject obj) {
        if (log.containsKey("type")) {
            String type = log.getStr("type");
            switch (type.trim().toLowerCase()) {
                case "smtp pop webmail":
                    obj.put("opt_subtype", "电子邮件");
                    break;
                case "webpage":
                    obj.put("opt_subtype", "网页浏览");
                    break;
                case "webbbs":
                    obj.put("opt_subtype", "网络言论");
                    break;
                case "oracle sqlserver mysql informix db2 postgresql sybase":
                    obj.put("opt_subtype", "数据库审计");
                    break;
                case "ftp telnet":
                    obj.put("opt_subtype", "服务器操作");
                    break;
                case "qq msn":
                    obj.put("opt_subtype", "即时通讯");
                    break;
                default:
                    obj.put("opt_subtype", type);
            }
        }
    }

    private static void disLogCat(JSONObject log, JSONObject obj) {
        if (log.containsKey("cat")) {
            String cat = log.getStr("cat");
            if (NumberUtil.isNumber(cat)) {
                switch (NumberUtil.parseInt(cat)) {
                    case 1:
                        obj.put("opt_type", "网页浏览");
                        childTypeParse("info0", "hostname", log, obj);
                        childTypeParse("info1", "url", log, obj);
                        break;
                    case 2:
                        obj.put("opt_type", "网络言论");
                        childTypeParse("info0", "url", log, obj);
                        childTypeParse("info1", "theme", log, obj);
                        childTypeParse("info2", "author", log, obj);
                        break;
                    case 3:
                        obj.put("opt_type", "表单提交");
                        childTypeParse("info0", "url", log, obj);
                        childTypeParse("info1", "method", log, obj);
                        break;
                    case 4:
                        obj.put("opt_type", "电子邮件");
                        childTypeParse("info0", "email_addresser", log, obj);
                        childTypeParse("info1", "email_recipients", log, obj);
                        childTypeParse("info2", "theme", log, obj);
                        childTypeParse("info4", "email_accessory", log, obj);
                        break;
                    case 5:
                        obj.put("opt_type", "即时通讯");
                        break;
                    case 6:
                        obj.put("opt_type", "文件传输");
                        childTypeParse("info0", "source_file", log, obj);
                        childTypeParse("info2", "file_size", log, obj);
                        break;
                    case 7:
                        obj.put("opt_type", "服务器操作");
                        childTypeParse("info1", "opt_command", log, obj);
                        break;
                    case 8:
                        obj.put("opt_type", "数据库操作");
                        childTypeParse("info0", "db_username", log, obj);
                        childTypeParse("info1", "db_client", log, obj);
                        childTypeParse("info2", "db_table_name", log, obj);
                        childTypeParse("info4", "db_table_sql", log, obj);
                        childTypeParse("info4", "opt_command", log, obj);
                        break;
                    default:
                        obj.put("opt_type", "未知");
                }
                childTypeParse("info10", "relevance_user", log, obj);
                obj.put("message_content", infoContent(log));
            } else {
                obj.put("opt_type", cat);
            }
        }
    }

    private static String infoContent(JSONObject log) {
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 11; i++) {
            String info = "info" + i;
            if (log.containsKey(info)) {
                content.append(info).append(":").append(log.getStr(info)).append(";");
            }
        }
        return content.toString();
    }

    private static void childTypeParse(String key, String objKey, JSONObject log, JSONObject obj) {
        if (log.containsKey(key)) {
            String val = log.getStr(key);
            if (StrUtil.isNotBlank(val)) {
                obj.put(objKey, val);
            }
        }
    }
}
