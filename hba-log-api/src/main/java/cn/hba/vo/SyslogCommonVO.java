package cn.hba.vo;

import lombok.Data;

/**
 * syslog 公共部分
 *
 * @author wbw
 * @date 2019/11/5 13:15
 */
@Data
public class SyslogCommonVO {
    /**
     * 原始日志信息
     */
    private String syslog;
    /**
     * 日志级别:
     * 0 - 紧急（系统已不可用）、1 - 警报（必须马上采取行动）、2 - 关键、3 - 错误、4 - 警告、5 - 通知（普通但重要的情形）、6 - 信息、7 - 调试
     */
    private Integer logLevel;
    /**
     * 日志业务类型，参考 《Api-日志业务说明》
     */
    private String logType;
    /**
     * 事件类型，参考 《事件类型参考表》
     */
    private String eventType;
    /**
     * 厂家名称，如：绿盟
     */
    private String manufacturersName;
    /**
     * 厂家设备，如：防火墙
     */
    private String manufacturersFacility;
    /**
     * 设备类型，如：ddos
     */
    private String facilityType;
    /**
     * 日志描述信息，如：绿盟 - 防火墙 - 内容过滤
     */
    private String logDes;
    /**
     * 中心时间
     */
    private String centerTime;
    /**
     * 系统类型为 system、audit
     */
    private String systemType = "system";
    /**
     * 模块类型为 safe、yunwei
     */
    private String moduleType = "safe";
    /**
     * 事件时间
     */
    private String eventTime;
}
