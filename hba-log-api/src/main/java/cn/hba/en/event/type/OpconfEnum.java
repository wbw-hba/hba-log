package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 操作配置
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum OpconfEnum {
    /**
     * 操作配置字段key及示意
     */
    BUSINESS("business","业务"),PAGE("page","页面"),
    AAA("aaa","AAA"),ACCOUNT("account","账户"),
    CONFIGURATION("configuration","配置"),USER("user","用户"),
    GATEWAY("gateway","网关"),MANAGE("manage","管理"),
    CERTIFICATE("certificate","证书"),FUNCTION("function","功能"),
    OTHER("other","其他");

    private String key;
    private String value;

    OpconfEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
