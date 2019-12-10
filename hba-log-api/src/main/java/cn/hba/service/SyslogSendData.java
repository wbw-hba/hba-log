package cn.hba.service;

import cn.hutool.json.JSONArray;

/**
 * syslog 数据发送
 * @author wbw
 * @date 2019/12/10 11:04
 */
public interface SyslogSendData {

    void send(JSONArray array);
}
