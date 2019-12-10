package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 运维审计
 *
 * @author wbw
 * @date 2019/12/9 15:33
 */
@Getter
public enum OperationEnum {
    /**
     * 操作配置字段key及示意
     */
    AUTH("auth", "身份验证"), OTHER("other", "其他"), PROPERTY("property", "资产"),
    COMMAND_FIREWALL("command_firewall", "命令防火墙"), SESSION("session", "会话");

    private String key;
    private String value;

    OperationEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
