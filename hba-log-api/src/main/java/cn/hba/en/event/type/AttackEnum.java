package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 攻击
 *
 * @author wbw
 * @date 2019年11月5日11:04:32
 */
@Getter
public enum AttackEnum {
    /**
     * 攻击字段key及示意
     */
    DDOS("ddos", "DDOS攻击"), PATH_THROUGH("path_through", "路径穿越攻击"),
    WEB("web", "Web攻击"), CATALOGUE_INDEX("catalogue_index", "目录索引"),
    EVENT("event", "攻击事件"), ILLEGAL_DOWNLOAD("illegal_download", "非法下载"),
    FLOW("flow", "流量攻击"), CUSTOM("custom", "自定义攻击"),
    HOST_INTRUSION("host_intrusion", "主机入侵"), COOKIE_TAMPER("cookie_tamper", "Cookie篡改"),
    SQL_INJECT("sql_inject", "SQL注入"), VIOLATE_WHITE_LIST("violate_white_list", "违背白名单"),
    XSS_SCRIPT("xss_script", "XSS跨站脚本攻击"), SENSITIVE_INFO_FILTER("sensitive_info_filter", "敏感信息过滤"),
    SPITE_FILE_UPLOADING("spite_file_uploading", "恶意非法文件上传"), BRUTE_FORCE("brute_force", "暴力破解攻击"),
    DYNAMITE("dynamite", "爆破攻击"), SUSTAIN_ATTACK_ENTRENCH("sustain_attack_entrench", "持续攻击防御"),
    WEB_SCAN("web_scan", "Web扫描"), INTUSION_DETECTION("intusion_detection", "入侵检测"),
    INVADE_DEFENSE("invade_defense", "入侵防护"), ATTACK_ENTRENCH("attack_entrench", "攻击防护"),
    WEB_LOOPHOLE("web_loophole", "Web漏洞攻击"), CONTENT_DECEIVE("catalogue_index", "内容欺骗"),
    SPITE_SCAN("spite_scan", "恶意扫描"), FUNCTION_ABUSE("function_abuse", "功能滥用"),
    XSS_REQUEST_FORGE("xss_request_forge", "跨站请求伪造"), FORMAT_CHAR("format_char", "格式化字符串攻击"),
    LDAP_INJECT("ldap_inject", "LDAP注入攻击"), ssi_inject("ssi_inject", "SSI注入"),
    XPATH_INJECT("xpath_inject", "XPath注入攻击"), CMD_INJECT("cmd_inject", "命令注入攻击"),
    APT("apt", "apt"), WAF("waf", "waf"), OTHER("other", "其他");

    private String key;
    private String value;

    AttackEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
