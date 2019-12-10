package cn.hba.audit.flume.util;

import cn.hutool.json.JSONObject;

/**
 * 攻击日志工具类
 *
 *
 * @author wbw
 * @date 2019/11/28 18.contains(type)){23
 */
public class AttackUtil {

    /**
     * 对已定义的类型处理
     *
     * @param ty  攻击名称
     * @param obj obj对象
     */
    public static void eventType(String ty, JSONObject obj) {
        String type = ty.toLowerCase();
        if ("dos攻击".contains(type)) {
            obj.put("event_type", "dos");
        } else if ("cc攻击".contains(type)) {
            obj.put("event_type", "cc");
        } else if ("ddos攻击".contains(type)) {
            obj.put("event_type", "ddos");
        } else if ("入侵检测".contains(type)) {
            obj.put("event_type", "ids");
        } else if ("waf攻击".contains(type)) {
            obj.put("event_type", "waf");
        } else if ("入侵防御".contains(type)) {
            obj.put("event_type", "ips");
        } else if ("apt攻击".contains(type)) {
            obj.put("event_type", "apt");
        } else {
            obj.put("event_type", "other");
        }
    }


    /**
     * 对已定义的子类型处理
     *
     * @param ty  攻击子类型名称
     * @param obj obj对象
     */
    public static void eventSonType(String ty, JSONObject obj) {
        String type = ty.toLowerCase();
        if ("sql注入".contains(type)) {
            obj.put("event_son_type", "sql_inject");
        } else if ("违背白名单".contains(type)) {
            obj.put("event_son_type", "violate_white_list");
        } else if ("xss跨站脚本攻击".contains(type)) {
            obj.put("event_son_type", "xss_script");
        } else if ("敏感信息过滤".contains(type)) {
            obj.put("event_son_type", "sensitive_info_filter");
        } else if ("恶意非法文件上传".contains(type)) {
            obj.put("event_son_type", "spite_file_uploading");
        } else if ("爆破攻击".contains(type)) {
            obj.put("event_son_type", "dynamite");
        } else if ("web扫描".contains(type)) {
            obj.put("event_son_type", "web_scan");
        } else if ("web漏洞攻击".contains(type)) {
            obj.put("event_son_type", "web_loophole");
        } else if ("内容欺骗".contains(type)) {
            obj.put("event_son_type", "catalogue_index");
        } else if ("恶意扫描".contains(type)) {
            obj.put("event_son_type", "spite_scan");
        } else if ("功能滥用".contains(type)) {
            obj.put("event_son_type", "function_abuse");
        } else if ("跨站请求伪造".contains(type)) {
            obj.put("event_son_type", "xss_request_forge");
        } else if ("格式化字符串攻击".contains(type)) {
            obj.put("event_son_type", "format_char");
        } else if ("ldap注入攻击".contains(type)) {
            obj.put("event_son_type", "ldap_inject");
        } else if ("ssi注入".contains(type)) {
            obj.put("event_son_type", "ssi_inject");
        } else if ("xpath注入攻击".contains(type)) {
            obj.put("event_son_type", "xpath_inject");
        } else if ("命令注入攻击".contains(type)) {
            obj.put("event_son_type", "cmd_inject");
        } else if ("cookie篡改".contains(type)) {
            obj.put("event_son_type", "cookie_tamper");
        } else if ("非法下载".contains(type)) {
            obj.put("event_son_type", "illegal_download");
        } else if ("路径穿越攻击".contains(type)) {
            obj.put("event_son_type", "path_through");
        } else if ("防篡改".contains(type)) {
            obj.put("event_son_type", "tamper_proofing");
        } else if ("用户自定义".contains(type)) {
            obj.put("event_son_type", "custom");
        } else if ("防爬虫".contains(type)) {
            obj.put("event_son_type", "reptile");
        } else if ("防扫描".contains(type)) {
            obj.put("event_son_type", "prevent_scan");
        } else if ("信息泄露".contains(type)) {
            obj.put("event_son_type", "infor_disclosure");
        } else if ("溢出".contains(type)) {
            obj.put("event_son_type", "overflow");
        } else if ("其它".contains(type)) {
            obj.put("event_son_type", "other");
        } else if ("协议完整性".contains(type)) {
            obj.put("event_son_type", "protocol_integrity");
        } else if ("防盗链".contains(type)) {
            obj.put("event_son_type", "csrf");
        } else if ("HTTP协议校验".contains(type)) {
            obj.put("event_son_type", "http_conformity");
        } else if ("HTTP访问控制".contains(type)) {
            obj.put("event_son_type", "http_acl");
        } else if ("特征防护".contains(type)) {
            obj.put("event_son_type", "signature");
        } else if ("文件下载".contains(type)) {
            obj.put("event_son_type", "download_file");
        } else if ("弱密码".contains(type)) {
            obj.put("event_son_type", "weak_pwd");
        } else {
            obj.put("event_son_type", type);
        }
    }
}
