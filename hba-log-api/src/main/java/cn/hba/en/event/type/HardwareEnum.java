package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 硬件
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum HardwareEnum {
    /**
     * 硬件字段key及示意
     */
    PLUG("plug", "插件"), PERIPHERALS("peripherals", "外设使用"),
    HARDWARE("hardware", "硬件"), POWER("power", "电源"),
    INTERFACE_BOARD("interface_board", "接口板"), OTHER("other", "其他");

    private String key;
    private String value;

    HardwareEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
