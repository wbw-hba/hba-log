package cn.hba.audit.flume.soc.exception.abandon;

import lombok.extern.slf4j.Slf4j;

/**
 * 主动丢弃日志
 *
 * @author wbw
 * @date 2020/1/6 11:15
 */
@Slf4j
public class AbandonLog {

    /**
     * 主动丢弃日志
     *
     * @param manufacturers 厂家
     * @param msg           日志内容
     * @return AbandonLog class
     */
    public static AbandonLog of(String manufacturers, String msg) {
        log.debug("Abandon the log,manufacturers:\t{},log:\t{}", manufacturers, msg);
        return new AbandonLog();
    }
}
