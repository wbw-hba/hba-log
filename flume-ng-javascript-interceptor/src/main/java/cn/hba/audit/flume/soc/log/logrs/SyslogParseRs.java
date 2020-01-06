package cn.hba.audit.flume.soc.log.logrs;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 瑞数 RAS
 *
 * @author wbw
 * @date 2019/12/3 13:56
 */
public class SyslogParseRs implements SyslogParse {
    @Override
    public Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        if (RsRasLog.isRas(syslog)){
            // 瑞数 ras 爬虫
            return RsRasLog.parse(syslog,obj);
        }
        return null;
    }

    public static void main(String[] args) {
        String syslog = "<142>Dec  4 18:12:43 box ParsedAccessLog: {\"hostname\":\"59.255.22.68:8050\",\"src_ip\":\"59.197.161.194\",\"time_local\":\"04/Dec/2019:18:12:42 +0800\",\"timestamp\":1575454362871,\"node_ip\":\"192.168.50.1\",\"attack_type\":[\"OK\"],\"action\":\"POST\",\"path\":\"/tacs-gov/login/csrfSave\",\"protocol\":\"HTTP/1.1\",\"req_len\":2017,\"status\":200,\"body_bytes_out\":83,\"referer\":\"http://59.255.22.68:8050/tacs-gov/login/loginJump\",\"user_agent\":\"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3928.4 Safari/537.36\",\"x_forwarded_for\":\"59.197.161.194\",\"content_type\":\"application/json\",\"charset\":\"charset=UTF-8\",\"all_upstream_addr\":\"192.168.50.11:8050\",\"upstream_retries\":1,\"upstream_addr\":\"192.168.50.11:8050\",\"upstream_status\":200,\"upstream_response_time\":0.004,\"request_time\":0.005,\"http_host\":\"59.255.22.68:8050\",\"remote_user\":\"\",\"resp_len\":495,\"args\":\"\",\"args_encrypted\":\"MmEwMD=4SCo444axX3h23yUr70ivnkvouf8a9441Mrqv57mYQy5nqF.w2p8dJ9_PAzFTg19qgMWEvI8jkj8v1E2YAom1iFCAYAxXXXPkqm2kO464.GwEcApkVncQfZG9ZXgypFMVAbjljiNX.NXa.Mo.H37DkPmzzi.m1agZlzo1uVIj_DWVCfQ8fu2IH5uXh4Yy6ZfcbP._eDnee5O9ejQK9LJg_VohCBPNgj0EMspCBydkFuQscp48NLFzv_JE5MqhhvlDoagpXyEblgAkvPI8xqdh.MdPG1luLntNvIWvdt2ShlPRtCBeRlyYtlIxpu7O93gkbSgby3KeRuZY_DmkB9lrrMXi_5FUxoF3vklFTl5TQ6jNZhtmQZxJGSdOmvVuIPChqGs\",\"attack_detect_browser_engine\":\"edge:chrome\",\"fingerprint_canvas\":\"Z2TKD23NxYwWn.QlomS5iPLBHA9\",\"fingerprint_font\":\"ME8CVTpv2TBOiYLWNZts6ucTlM0\",\"fingerprint_webgl\":\"PTw_2X0vU2AzM3YOSgYqomp3oPE\",\"fingerprint_browser\":\"EhPUJ8VV6bKPkDX4p4BXv1hi7Kf7\",\"attack_detect_browser_type\":\"Chrome\",\"attack_detect_browser_match_ua\":true,\"battery_level\":100,\"battery_charging_time\":0,\"battery_is_charging\":true,\"connection_type\":\"UNKNOWN\",\"protect_level\":0,\"unif_block_action_log\":\"1#2#9\",\"action_delay\":0.000,\"dr_uri\":\"OK\",\"dr_refer\":\"OK\",\"dr_cookie\":\"OK\",\"dr_post\":\"OK\",\"cookie_create_date\":\"2019-12-4\",\"cookie_id_cur\":\"12801_17677966971650\",\"cookie_id_steady\":\"12801_17677966971650\",\"in_blacklist_ip\":false,\"is_ajax\":true,\"ua_browser\":\"Chrome\",\"ua_device\":\"Unknown\",\"ua_browser_versi\n";
        SyslogParseRs rs = new SyslogParseRs();
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog",syslog);

        Object parse = rs.parse(obj.toString());
        System.out.println(JSONUtil.parse(parse).toJSONString(2));
    }
}
