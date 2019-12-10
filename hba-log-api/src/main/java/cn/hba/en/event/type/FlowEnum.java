package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 流量
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum FlowEnum {
    /**
     * 流量字段key及示意
     */
    TRACTION("traction", "牵引"), FLOW("flow", "流量"), BANDWIDTH("bandwidth", "带宽"),
    INFO_REVEAL("info_reveal", "信息泄露"), OTHER("other", "其他");

    private String key;
    private String value;

    FlowEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
