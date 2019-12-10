package cn.hba.service;

import cn.hutool.json.JSONArray;

/**
 * syslog 数据发送
 *
 * @author wbw
 * @date 2019/12/10 11:04
 */
public interface SyslogSendData {
    /**
     * 发送数据
     *
     * @param array 数组
     */
    void send(JSONArray array);
}
