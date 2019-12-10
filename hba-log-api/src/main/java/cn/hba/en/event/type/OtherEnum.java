package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 其他
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum OtherEnum {
    /**
     * 其他字段key及示意
     */
    OTHER("other", "其他");

    private String key;
    private String value;

    OtherEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
