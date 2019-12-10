package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 威胁
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum MenaceEnum {
    /**
     * 威胁 字段key及示意
     */
    BOTNET("botnet", "僵尸网络"), GARBAGE_FILTERING("garbage_filtering", "圾邮件过滤"),
    CC("cc", "CC"), THREAT_INTELLIGENCE("threat_intelligence", "威胁情报"),
    DOS("dos", "拒绝服务"), UNNECESSARY_SERVICE("unnecessary_service", "不必要的服务"),
    REMOTE_DATA("remote_data", "远程数据修改"),POLICY_VIOLATION("policy_violation","隐私策略违反"),	SCAN("scan","扫描"),
    WEIRD_BEHAVIOR("weird_behavior","异常行为"),OTHER("other", "其他");

    private String key;
    private String value;

    MenaceEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
