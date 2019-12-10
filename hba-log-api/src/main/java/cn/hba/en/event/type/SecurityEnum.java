package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 安全
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum SecurityEnum {
    /**
     * 安全字段key及示意
     */
    VULNERABILITY("vulnerability", "漏洞"), VIRUS("virus", "病毒"),
    EXPERIENCE_HEALTH("experience_health", "健康体验"), XP_SHIELD("xp_shield", "Xp盾甲"),
    VIOLATION("violation", "违规"), SYS_REPAIR("sys_repair", "系统修复"),
    FW("fw", "防火墙"), DESKTOP_REINFORCE("desktop_reinforce", "桌面加固"),
    SECRET_KEY_ERROR("secret_key_error", "秘钥错误"), WEB_SAFETY("web_safety", "Web安全"),
    RUBBISH_EMAIL("rubbish_email", "反垃圾邮件"), TAMPER("tamper", "篡改"),
    ARP_ENTRENCH("arp_entrench", "ARP防护"), SESSION_TRACE("session_trace", "会话追踪"),
    HIGH_RISK_IP("high_risk_ip", "高危IP"), BLACKLIST("blacklist", "黑名单"),
    TERMINAL_SECURITY("terminal_security", "终端安全"), OTHER("other", "其他");

    private String key;
    private String value;

    SecurityEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
