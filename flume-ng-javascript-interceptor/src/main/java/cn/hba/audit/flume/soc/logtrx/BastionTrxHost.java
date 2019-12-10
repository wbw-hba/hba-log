package cn.hba.audit.flume.soc.logtrx;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 天融信 堡垒机
 *
 * @author lizhi
 * @date 2019/9/16 16:24
 */
public class BastionTrxHost {


    public static JSONObject parse(String body) {
        String syslog = JSONUtil.parseObj(body).getStr("syslog");
        JSONObject jsonObject = ParseMessageKv.parseMessage6(syslog);
        JSONObject obj = new JSONObject();
        obj.put("log_type", "fw");
        obj.put("manufacturers_name", "trx");
        String strType = null;
        if (jsonObject.containsKey("id")) {
            obj.put("procid", jsonObject.getStr("id"));
        }

        if (jsonObject.containsKey("time")) {
            obj.put("event_time", jsonObject.getStr("time"));
        }

        if (jsonObject.containsKey("fw")) {
            obj.put("app_name", jsonObject.getStr("fw"));
        }
        if (jsonObject.containsKey("type")) {
            strType = jsonObject.getStr("type");
            obj.put("event_type", jsonObject.getStr("type"));
        }
        if (jsonObject.containsKey("pri")) {
            obj.put("event_level", jsonObject.getStr("pri"));
        }

        if (jsonObject.containsKey("rule")) {
            if ("ac".equalsIgnoreCase(strType) || "pf".equalsIgnoreCase(strType)) {
                obj.put("modify_type", jsonObject.getStr("rule"));
            } else if ("file_block".equalsIgnoreCase(strType)) {
                obj.put("file_rule_name", jsonObject.getStr("rule"));
            } else {
                obj.put("fw_rule_id", jsonObject.getStr("rule"));
            }
        }
        disLogMsg5(jsonObject, obj);
        if (jsonObject.containsKey("*dmac")) {
            obj.put("destination_mac", jsonObject.getStr("*dmac"));
        }
        disLogMsg4(jsonObject, obj);
        if (jsonObject.containsKey("appname")) {
            obj.put("application_name", jsonObject.getStr("appname"));
        }
        disLogMsg3(jsonObject, obj);
        if (jsonObject.containsKey("modname")) {
            obj.put("mod_name", jsonObject.getStr("modname"));
        }

        disLogMsg2(jsonObject, obj);
        if (jsonObject.containsKey("abnormal_warning_type")) {
            obj.put("abnormal_warning_type", jsonObject.getStr("abnormal_warning_type"));
        }
        disLogMsg1(jsonObject, obj);
        obj.put("log_des", "天融信 - 防火墙 - " + obj.getStr("event_type"));
        return obj;
    }

    private static void disLogMsg5(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("proto")) {
            obj.put("destination_protocol", jsonObject.getStr("proto"));
        }

        if (jsonObject.containsKey("duration")) {
            obj.put("duration_time", jsonObject.getStr("duration"));
        }

        if (jsonObject.containsKey("sent")) {
            obj.put("sent", jsonObject.getStr("sent"));
        }

        if (jsonObject.containsKey("rcvd")) {
            obj.put("rcvd", jsonObject.getStr("rcvd"));
        }

        if (jsonObject.containsKey("src")) {
            obj.put("source_ip", jsonObject.getStr("src"));
        }

        if (jsonObject.containsKey("dst")) {
            obj.put("destination_ip", jsonObject.getStr("dst"));
        }

        if (jsonObject.containsKey("user")) {
            obj.put("user_name", jsonObject.getStr("user"));
        }
        if (jsonObject.containsKey("op")) {
            obj.put("act", jsonObject.getStr("op"));
        }
        if (jsonObject.containsKey("result")) {
            obj.put("result", jsonObject.getStr("result"));
        }
        if (jsonObject.containsKey("arg")) {
            obj.put("arg", jsonObject.getStr("arg"));
        }

        if (jsonObject.containsKey("msg")) {
            obj.put("message_content", jsonObject.getStr("msg"));
        }
        if (jsonObject.containsKey("*sport")) {
            obj.put("source_port", jsonObject.getStr("*sport"));
        }
        if (jsonObject.containsKey("*dport")) {
            obj.put("destination_port", jsonObject.getStr("*dport"));
        }
        if (jsonObject.containsKey("*smac")) {
            obj.put("source_mac", jsonObject.getStr("*smac"));
        }
    }

    private static void disLogMsg4(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("sport")) {
            obj.put("source_port", jsonObject.getStr("*sport"));
        }
        if (jsonObject.containsKey("dport")) {
            obj.put("destination_port", jsonObject.getStr("*dport"));
        }
        if (jsonObject.containsKey("smac")) {
            obj.put("source_mac", jsonObject.getStr("*smac"));
        }
        if (jsonObject.containsKey("dmac")) {
            obj.put("destination_mac", jsonObject.getStr("*dmac"));
        }
        if (jsonObject.containsKey("*recorder")) {
            obj.put("loophole_name", jsonObject.getStr("*recorder"));
        }
        if (jsonObject.containsKey("recorder")) {
            obj.put("loophole_name", jsonObject.getStr("recorder"));
        }
        if (jsonObject.containsKey("inpkt")) {
            obj.put("inpkt", jsonObject.getStr("inpkt"));
        }
        if (jsonObject.containsKey("outpkt")) {
            obj.put("outpkt", jsonObject.getStr("outpkt"));
        }
        if (jsonObject.containsKey("connid")) {
            obj.put("connid", jsonObject.getStr("connid"));
        }
        if (jsonObject.containsKey("parentid")) {
            obj.put("parentid", jsonObject.getStr("parentid"));
        }
        if (jsonObject.containsKey("policyid")) {
            obj.put("ruleid", jsonObject.getStr("policyid"));
        }
        if (jsonObject.containsKey("dpiid")) {
            obj.put("dpi_id", jsonObject.getStr("dpiid"));
        }
        if (jsonObject.containsKey("visd")) {
            obj.put("visd", jsonObject.getStr("visd"));
        }
        if (jsonObject.containsKey("dev")) {
            obj.put("app_name", jsonObject.getStr("dev"));
        }
        if (jsonObject.containsKey("version")) {
            obj.put("version", jsonObject.getStr("version"));
        }
        if (jsonObject.containsKey("method")) {
            obj.put("method", jsonObject.getStr("method"));
        }
        if (jsonObject.containsKey("sdev")) {
            obj.put("in_ifname", jsonObject.getStr("sdev"));
        }
        if (jsonObject.containsKey("ddev")) {
            obj.put("out_ifname", jsonObject.getStr("ddev"));
        }
        if (jsonObject.containsKey("protoid")) {
            obj.put("protoid", jsonObject.getStr("protoid"));
        }
        if (jsonObject.containsKey("vsys_name")) {
            obj.put("vsys_name", jsonObject.getStr("vsys_name"));
        }
    }

    private static void disLogMsg3(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("action")) {
            obj.put("modify_type", jsonObject.getStr("action"));
        }
        if (jsonObject.containsKey("idsip")) {
            obj.put("idsip", jsonObject.getStr("idsip"));
        }
        if (jsonObject.containsKey("protoname")) {
            obj.put("destination_protocol", jsonObject.getStr("protoname"));
        }
        if (jsonObject.containsKey("url")) {
            obj.put("url", jsonObject.getStr("url"));
        }
        if (jsonObject.containsKey("sender")) {
            obj.put("sender", jsonObject.getStr("sender"));
        }
        if (jsonObject.containsKey("receiver")) {
            obj.put("recipient", jsonObject.getStr("receiver"));
        }
        if (jsonObject.containsKey("cc")) {
            obj.put("cc", jsonObject.getStr("cc"));
        }
        if (jsonObject.containsKey("bcc")) {
            obj.put("bcc", jsonObject.getStr("bcc"));
        }
        if (jsonObject.containsKey("subject")) {
            obj.put("title", jsonObject.getStr("subject"));
        }
        if (jsonObject.containsKey("command")) {
            obj.put("act", jsonObject.getStr("command"));
        }
        if (jsonObject.containsKey("filename")) {
            obj.put("destination_file", jsonObject.getStr("filename"));
        }
        if (jsonObject.containsKey("virus_name")) {
            obj.put("loophole_name", jsonObject.getStr("virus_name"));
        }
        if (jsonObject.containsKey("profile")) {
            obj.put("profile", jsonObject.getStr("profile"));
        }
        if (jsonObject.containsKey("subtype")) {
            obj.put("url_subtype", jsonObject.getStr("subtype"));
        }
        if (jsonObject.containsKey("cat_name")) {
            obj.put("cat_name", jsonObject.getStr("cat_name"));
        }
        if (jsonObject.containsKey("groupname")) {
            obj.put("group_name", jsonObject.getStr("groupname"));
        }
        if (jsonObject.containsKey("field")) {
            obj.put("field", jsonObject.getStr("field"));
        }
    }

    private static void disLogMsg2(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("sub_type")) {
            obj.put("event_type", jsonObject.getStr("sub_type"));
        }
        if (jsonObject.containsKey("dst_addr")) {
            obj.put("destination_ip", jsonObject.getStr("dst_addr"));
        }
        if (jsonObject.containsKey("zonename")) {
            obj.put("zone_name", jsonObject.getStr("zonename"));
        }
        if (jsonObject.containsKey("grpname")) {
            obj.put("grpname", jsonObject.getStr("grpname"));
        }
        if (jsonObject.containsKey("src_addr")) {
            obj.put("source_ip", jsonObject.getStr("src_addr"));
        }
        if (jsonObject.containsKey("service")) {
            obj.put("loophole_type", jsonObject.getStr("service"));
        }
        if (jsonObject.containsKey("attack_status")) {
            obj.put("status", jsonObject.getStr("attack_status"));
        }
        if (jsonObject.containsKey("protocol_4")) {
            obj.put("destination_protocol", jsonObject.getStr("protocol_4"));
        }
        if (jsonObject.containsKey("dst_port")) {
            obj.put("destination_port", jsonObject.getStr("dst_port"));
        }
        if (jsonObject.containsKey("attack_type")) {
            obj.put("attack_type", jsonObject.getStr("attack_type"));
        }
        if (jsonObject.containsKey("defense_method")) {
            obj.put("defense_method", jsonObject.getStr("defense_method"));
        }
        if (jsonObject.containsKey("cur_cfg_value")) {
            obj.put("cur_cfg_value", jsonObject.getStr("cur_cfg_value"));
        }
        if (jsonObject.containsKey("cfg_value_unit")) {
            obj.put("cfg_value_unit", jsonObject.getStr("cfg_value_unit"));
        }
        if (jsonObject.containsKey("total_packets")) {
            obj.put("total_packets", jsonObject.getStr("total_packets"));
        }
        if (jsonObject.containsKey("atack_packets")) {
            obj.put("atack_packets", jsonObject.getStr("atack_packets"));
        }
        if (jsonObject.containsKey("total_bytes")) {
            obj.put("total_bytes", jsonObject.getStr("total_bytes"));
        }
        if (jsonObject.containsKey("attack_bytes")) {
            obj.put("attack_bytes", jsonObject.getStr("attack_bytes"));
        }
        if (jsonObject.containsKey("data_action")) {
            obj.put("data_action", jsonObject.getStr("data_action"));
        }
        if (jsonObject.containsKey("attack_msgs")) {
            obj.put("message_content", jsonObject.getStr("attack_msgs"));
        }

        if (jsonObject.containsKey("abnormal_obj_name")) {
            obj.put("abnormal_obj_name", jsonObject.getStr("abnormal_obj_name"));
        }
    }

    private static void disLogMsg1(JSONObject jsonObject, JSONObject obj) {
        if (jsonObject.containsKey("abnormal_condition")) {
            obj.put("abnormal_condition", jsonObject.getStr("abnormal_condition"));
        }
        if (jsonObject.containsKey("condition_type")) {
            obj.put("condition_type", jsonObject.getStr("condition_type"));
        }
        if (jsonObject.containsKey("cs_obj")) {
            obj.put("cs_obj", jsonObject.getStr("cs_obj"));
        }

        if (jsonObject.containsKey("trans_sip")) {
            obj.put("translated_source_ip", jsonObject.getStr("trans_sip"));
        }
        if (jsonObject.containsKey("trans_dip")) {
            obj.put("translated_destination_ip", jsonObject.getStr("trans_dip"));
        }
        if (jsonObject.containsKey("trans_sport")) {
            obj.put("original_source_port", jsonObject.getStr("trans_sport"));
        }
        if (jsonObject.containsKey("trans_dport")) {
            obj.put("translated_destination_port", jsonObject.getStr("trans_dport"));
        }
        if (jsonObject.containsKey("rcv_pkt")) {
            obj.put("inpkt", jsonObject.getStr("rcv_pkt"));
        }
        if (jsonObject.containsKey("send_pkt")) {
            obj.put("outpkt", jsonObject.getStr("send_pkt"));
        }
        if (jsonObject.containsKey("rcv_bytes")) {
            obj.put("rcvd", jsonObject.getStr("rcv_bytes"));
        }
        if (jsonObject.containsKey("send_bytes")) {
            obj.put("sent", jsonObject.getStr("send_bytes"));
        }
        if (jsonObject.containsKey("direction")) {
            obj.put("direction", jsonObject.getStr("direction"));
        }
        if (jsonObject.containsKey("filetype")) {
            obj.put("filetype", jsonObject.getStr("filetype"));
        }
        if (jsonObject.containsKey("tid")) {
            obj.put("fw_rule_id", jsonObject.getStr("tid"));
        }
        if (jsonObject.containsKey("appendix")) {
            obj.put("alert_info", jsonObject.getStr("appendix"));
        }
        if (jsonObject.containsKey("application")) {
            obj.put("App/Protocol", jsonObject.getStr("application"));
        }
    }

    public static void main(String[] args) {
        String syslog = "id=tos time=\"2019-09-19 14:35:34\" fw=TopsecOS pri=5 type=mgmt user=superman src=2.74.24.29 result=0 recorder=config msg=\"log log type_set add mgmt\" ";
        JSONObject parse = parse(syslog);
        System.out.println(parse.toJSONString(2));
    }

}
