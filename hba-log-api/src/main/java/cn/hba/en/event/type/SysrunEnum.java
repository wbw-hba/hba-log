package cn.hba.en.event.type;

import lombok.Getter;

/**
 * 系统运行
 *
 * @author wbw
 * @date 2019年11月5日11:18:45
 */
@Getter
public enum SysrunEnum {
    /**
     * 系统运行字段key及示意
     */
    CPU("cpu", "cpu"), MEM("mem", "内存"),
    DISK("disk", "硬盘"), SYSTEM("system", "系统"),
    CMD("cmd", "命令"), FILE("file", "文件"),
    VERSION("version", "版本"), COURSE("course", "进程"),
    LONG_RANGE("long_range", "远程"), CONTROLLER("controller", "控制器"),
    PORT("port", "端口"), SERVER("server", "服务"),
    IDS("ids", "IDS"), UPGRADE("upgrade", "升级"),
    FACILITY_MANAGE("facility_manage", "设备管理"), WIRELESS("wireless", "无线"),
    DUPLICATED_HR("duplicated_hr", "双机热备"), TIME("time", "时间"),
    HOST("host", "主机"), OTHER("other", "其他");

    private String key;
    private String value;

    SysrunEnum(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
