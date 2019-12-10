package cn.hba.en.log.type;

import lombok.Getter;

/**
 * 日志类型
 *
 * @author Wbw
 * @date 2019年11月5日13:26:02
 */
@Getter
public enum LogTypeEnum {
    /**
     * 字段key及示意
     */
    ATTACK("attack", "攻击"), FLOW("flow", "流量"),
    MENACE("menace", "威胁"), STRATEGY("strategy", "策略规则"),
    SYSRUN("sysrun", "系统运行"), OPCONF("opconf", "操作配置"),
    SECURITY("security", "安全"), HARDWARE("hardware", "硬件"),
    NETWORK("network", "网络"), OTHER("other", "其他");


    private String key;
    private String value;

    LogTypeEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
