package cn.hba.service;

/**
 * syslog 接收处理
 *
 * @author wbw
 * @date 2019/11/5 9:27
 */
public interface SyslogReceptionService {
    /**
     * 处理 syslog
     *
     * @param ip   用户真实ip
     * @param json syslog
     * @return true or false
     */
    boolean disSyslog(String json, String ip);
}
