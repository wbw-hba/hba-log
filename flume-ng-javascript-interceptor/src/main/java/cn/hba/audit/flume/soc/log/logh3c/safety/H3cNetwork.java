package cn.hba.audit.flume.soc.log.logh3c.safety;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;

/**
 * 日志网络
 *
 * @author wbw
 * @date 2020/1/7 10:32
 */
class H3cNetwork {
    /**
     * Ping statistics for 192.168.6.1: 5 packet(s) transmitted, 5 packet(s) received, 0.0% packet loss, round-trip min/avg/max/std-dev = 3.138/5.111/11.086/3.021 ms.
     *
     * @param bo  内容
     * @param obj 对象
     */
    static void disPingLog(String bo, JSONObject obj) {
        String type = bo.trim().split(" ")[0];
        obj.put("type", type.toLowerCase());
        String ip = bo.split("statistics for ")[1].split(" packet(s)")[0].trim();
        obj.put("dest_ip", ip.split(":")[0].trim());
        obj.put("req_num", NumberUtil.parseNumber(ip.split(":")[1].trim()));
        int index = bo.indexOf(" packet(s) received");
        obj.put("res_num", NumberUtil.parseNumber(bo.substring(index - 1, index)));

        String[] unMessageRatio = bo.split("% packet loss")[0].split(" ");
        obj.put("un_message_ratio", NumberUtil.parseNumber(unMessageRatio[unMessageRatio.length - 1]));
        String time = bo.split("= ")[1];
        String[] ms = StrUtil.trim(time.split("ms")[0]).split("/");
        obj.put("min_back_time", ms[0]);
        obj.put("ave_back_time", ms[1]);
        obj.put("max_back_time", ms[2]);
        obj.put("back_time_gap", ms[3]);
    }
}
