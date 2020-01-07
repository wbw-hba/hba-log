package cn.hba.audit.flume.soc.exception.abandon;


import java.util.UUID;

/**
 * 主动丢弃常量
 *
 * @author wbw
 * @date 2020/1/7 11:34
 */
public class AbandonConstant {
    /**
     * 主动丢弃标识
     */
    public static final String ABANDON = UUID.randomUUID().toString();
}
