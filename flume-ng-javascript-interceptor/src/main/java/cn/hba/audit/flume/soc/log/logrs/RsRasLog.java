package cn.hba.audit.flume.soc.log.logrs;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 瑞数 RAS 日志解析
 *
 * @author wbw
 * @date 2019/12/3 13:58
 */
public class RsRasLog {
    /**
     * 是否为 ras 日志
     */
    static boolean isRas(String syslog) {
        syslog = StrUtil.trim(syslog);
        String[] split = syslog.split(": \\{\"");
        if (split.length > 1) {
            syslog = "{\"" + split[1];
        }
        if (!JSONUtil.isJsonObj(syslog)) {
            return disLoseLog(StrUtil.trim(syslog));
        }
        JSONObject object = JSONUtil.parseObj(syslog);
        return object.containsKey("hostname") && object.containsKey("src_ip");
    }

    /**
     * 数据丢失处理验证
     * {"hostname":"dzzz.gjzwfw.gov.cn:8080","src_ip":"192.168.101.15","time_local":"04/Dec/2019:18:08:31 +0800",
     * "timestamp":1575454111016,"node_ip":"192.168.101.18","attack_type":["OK"],"action":"POST",
     * "path":"/elssp/sysMenu/getSysMenuByPId/38","protocol":"HTTP/1.1","req_len":1458,"status":200,
     * "body_bytes_out":312,"referer":"https://dzzz.gjzwfw.gov.cn:8080/elssp/showServiceTree",
     * "user_agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36",
     * "x_forwarded_for":"","content_type":"application/json","charset":"charset=UTF-8","all_upstream_addr":"192.168.101.4:8080",
     * "upstream_retries":1,"upstream_addr":"192.168.101.4:8080","upstream_status":200,"upstream_response_time":0.168,
     * "request_time":0.168,"http_host":"dzzz.gjzwfw.gov.cn:8080","remote_user":"","resp_len":504,"args":"",
     * "args_encrypted":"MmEwMD=4X4goWi.a_azvtnBwgZnu83vkq4ebO4nTtBe0YwoEFYQ0g5yoyWF9GVMGBiYQfkdM_1jBDWXM6_1oLZtT1iyxw6OhXOfuc4ysaoygZ2h
     * g5.0eNNAkFnNTGvknYwHbYDYn0Omjx12ocDEbUHUeUf4RoJcxb_z9Ma9d8tRAWwAMumj5geV6IbFESEQS6SZqs_C2g4BwsvTAmR1imrY2H1tTFwb_d2V_gE8ZLkAbXZ
     * bnTupyK.YAvjaDJf7COt2u57etB8H82KeK8hIlztYglQOwwScHGZohL0MPdwXbcJTBhZOBuIQ2x591CmbYJ0V5tgcuDbgD..pGR5JSFqLbjzM0kk7uKk9Xg.ggu.M
     * uRJ8n1N.CaQAfppt9.mVoTjc54.DsGVK","attack_detect_browser_engine":"edge:chrome","fingerprint_canvas":"rY_D5BZTkqzBWp7jNpoVce.Jro3",
     * "fingerprint_font":"t5vkmXwuUtqfnaX42LaFxHN6SJ9","fingerprint_webgl":"GRaVEwtXsjVba2.1rcVkvHMsF8Z",
     * "fingerprint_browser":"Ezpi0R138eiaP6ksGJwBZJQG6WUE","attack_detect_browser_type":"Chrome","attack_detect_browser_match_ua":true,
     * "connection_type":"UNKNOWN","protect_level":0,"unif_block_action_log":"1#2#9","action_delay":0.000,"dr_uri":"OK",
     * "dr_refer":"OK","dr_cookie":"OK","dr_post":"OK","cookie_create_date":"2019-9-21","cookie_id_cur":"25874_10127264483514",
     * "cookie_id_steady":"25874_5381365432321","cookie_id_changed_count":5,"in_blacklist_ip":false,"is_ajax":true,
     * "ua_browser":"Chrome","ua_device":"Unknown","ua_browser_version":"76.0.3809","ua_os":"Windows","ua_os_version":"7","data_collection_s
     *
     * @param syslog syslog
     * @return boolean
     */
    private static boolean disLoseLog(String syslog) {
        if (syslog.startsWith("<")) {
            return false;
        }
        syslog = syslog.substring(0, syslog.lastIndexOf("\",") + 1) + "}";
        JSONObject object = JSONUtil.parseObj(syslog);
        return object.containsKey("hostname") && object.containsKey("src_ip");
    }

    /**
     * 日志格式：
     * <142>Dec  1 19:26:27 box ParsedAccessLog:
     * {"hostname":"59.255.22.72:8089","src_ip":"59.200.105.1","time_local":"01/Dec/2019:19:26:27 +0800",
     * "timestamp":1575199587781,"node_ip":"192.168.103.60","attack_type":["OK"],"action":"POST",
     * "path":"/aic/rest/service/safety/refreshsecret","protocol":"HTTP/1.1","req_len":405,"status":200,
     * "body_bytes_out":206,"referer":"","user_agent":"Jakarta Commons-HttpClient/3.1","x_forwarded_for":"59.200.105.1",
     * "content_type":"text/plain","charset":"charset=UTF-8","all_upstream_addr":"192.168.103.2:8089",
     * "upstream_retries":1,"upstream_addr":"192.168.103.2:8089","upstream_status":200,"upstream_response_time":0.108,
     * "request_time":0.109,"http_host":"59.255.22.72","remote_user":"","resp_len":391,"args":"",
     * "args_encrypted":"","protect_level":0,"unif_block_action_log":"1#1#9","action_delay":0.000,
     * "invalid_request_action":"Pass","dr_uri":"OK","dr_refer":"OK","dr_cookie":"OK","dr_post":"OK",
     * "cookie_create_date":"1999-9-9","in_blacklist_ip":false,"post_url_form_encoded":true,
     * "ua_browser":"Jakarta Commons-HttpClient","ua_device":"Unknown","ua_browser_version":"3.1",
     * "ua_os":"Unknown","data_collection_stage":"NONE","is_learning_mode":true,"page_id":0,
     * "is_aiwaf_in_learning_mode":0,"aiwaf_status":0,"aiwaf_attack_confidence":0}
     */
    public static Object parse(String syslog, JSONObject obj) {
        // 公共部分处理 : {"
        if (syslog.contains(": {\"")) {
            String[] split = syslog.split(": \\{\"");
            String[] abs = split[0].split(" ");
            obj.put("abstract", abs[abs.length - 1] + " " + abs[abs.length - 2]);
            syslog = StrUtil.trim("{\"" + split[1]);
        }
        if (!JSONUtil.isJsonObj(syslog)) {
            syslog = syslog.substring(0, syslog.lastIndexOf("\",") + 1) + "}";
        }
        // 处理主体内容
        disLog(syslog, obj);
        // 必备字段处理
        obj.put("log_type", "attack");
        obj.put("event_type", "waf");
        obj.put("event_son_type", "reptile");
        obj.put("manufacturers_name", "瑞数");
        obj.put("manufacturers_facility", "RSA");
        obj.put("facility_type", "爬虫");
        obj.put("log_des", "瑞数 - RSA - 防爬信息");
        return obj;
    }

    private static void disLog(String syslog, JSONObject obj) {
        JSONObject sysJson = JSONUtil.parseObj(syslog);
        if (sysJson.containsKey("hostname")) {
            obj.put("facility_hostname", sysJson.getStr("hostname"));
        }
        if (sysJson.containsKey("src_ip")) {
            obj.put("ip", sysJson.getStr("ip"));
        }
        if (sysJson.containsKey("timestamp")) {
            obj.put("event_time", DateUtil.date(sysJson.getLong("timestamp")).toString());
        }
        if (sysJson.containsKey("node_ip")) {
            obj.put("node_ip", sysJson.getStr("node_ip"));
        }
        if (sysJson.containsKey("attack_type")) {
            obj.put("attack_type", sysJson.getStr("attack_type"));
        }
        if (sysJson.containsKey("action")) {
            obj.put("http_method", sysJson.getStr("action"));
        }
        if (sysJson.containsKey("path")) {
            obj.put("path", sysJson.getStr("path"));
        }
        if (sysJson.containsKey("protocol")) {
            obj.put("http_protocol", sysJson.getStr("protocol"));
        }
        if (sysJson.containsKey("req_len")) {
            obj.put("req_content_len", sysJson.getStr("req_len"));
        }
        if (sysJson.containsKey("status")) {
            obj.put("http_status", sysJson.getStr("status"));
        }
        if (sysJson.containsKey("referer")) {
            obj.put("referer", sysJson.getStr("referer"));
        }
        if (sysJson.containsKey("user_agent")) {
            obj.put("browser_agent", sysJson.getStr("user_agent"));
        }
        if (sysJson.containsKey("x_forwarded_for")) {
            obj.put("x_forwarded_for", sysJson.getStr("x_forwarded_for"));
        }
        if (sysJson.containsKey("content_type")) {
            obj.put("content_type", sysJson.getStr("content_type"));
        }
        if (sysJson.containsKey("charset")) {
            obj.put("charset", sysJson.getStr("charset"));
        }
        if (sysJson.containsKey("all_upstream_addr")) {
            obj.put("all_upstream_addr", sysJson.getStr("all_upstream_addr"));
        }
        if (sysJson.containsKey("upstream_addr")) {
            obj.put("upstream_addr", sysJson.getStr("upstream_addr"));
        }
        if (sysJson.containsKey("upstream_status")) {
            obj.put("upstream_status", sysJson.getStr("upstream_status"));
        }
        if (sysJson.containsKey("upstream_response_time")) {
            obj.put("upstream_response_time", sysJson.getDouble("upstream_response_time"));
        }
        if (sysJson.containsKey("request_time")) {
            obj.put("request_time", sysJson.getDouble("request_time"));
        }
        if (sysJson.containsKey("http_host")) {
            obj.put("http_host", sysJson.getStr("http_host"));
        }
        if (sysJson.containsKey("remote_user")) {
            obj.put("remote_user", sysJson.getStr("remote_user"));
        }
        if (sysJson.containsKey("resp_len")) {
            obj.put("res_content_len", sysJson.getStr("resp_len"));
        }
        if (sysJson.containsKey("args")) {
            obj.put("args", sysJson.getStr("args"));
        }
        if (sysJson.containsKey("action_delay")) {
            obj.put("action_delay", sysJson.getStr("action_delay"));
        }
        if (sysJson.containsKey("invalid_request_action")) {
            obj.put("invalid_request_action", sysJson.getStr("invalid_request_action"));
        }
        if (sysJson.containsKey("cookie_create_date")) {
            obj.put("cookie_create_date", sysJson.getStr("cookie_create_date"));
        }
        if (sysJson.containsKey("ua_browser")) {
            obj.put("ua_browser", sysJson.getStr("ua_browser"));
        }
        if (sysJson.containsKey("ua_device")) {
            obj.put("ua_device", sysJson.getStr("ua_device"));
        }
        if (sysJson.containsKey("ua_browser_version")) {
            obj.put("ua_browser_version", sysJson.getStr("ua_browser_version"));
        }
        if (sysJson.containsKey("ua_os")) {
            obj.put("ua_os", sysJson.getStr("ua_os"));
        }
        if (sysJson.containsKey("data_collection_stage")) {
            obj.put("data_collection_stage", sysJson.getStr("data_collection_stage"));
        }
    }
}
