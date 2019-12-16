package cn.hba.syslog.service;

import cn.hutool.json.JSONArray;

import java.io.Serializable;

/**
 * 基础公共类
 *
 * @author wbw
 * @date 2019/12/16 14:59
 */
public interface LogBase extends Serializable {
    /**
     * 流处理
     *
     * @param val 处理内容
     */
    void stream(JSONArray val);
}
