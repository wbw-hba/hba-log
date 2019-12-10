package cn.hba.audit.flume.soc;

/**
 * 解析实体
 *
 * @author wbw
 * @date 2019/9/6 10:54
 */
public interface SyslogParse {
    /**
     * 解析
     *
     * @param body 内容
     * @return Object
     */
    Object parse(String body);
}
