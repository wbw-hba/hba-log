package cn.hba.audit.flume.soc.loghw;

import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 华为交换机日志解析
 *
 * @author wbw
 * @date 2019/9/17 9:07
 */
public class InterchangerParse {


    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        obj.put("manufacturers_name", "hw");
        obj.put("log_type", "interchanger");
        if (isHwLog1(syslog)) {
            parseMsg1(syslog, obj);
            return logParse1(obj);
        } else if (isHwLog2(syslog)) {
            parseMsg2(syslog, obj);
            return logParse2(obj);
        } else if (isHwLog3(syslog)) {
            parseMsg3(syslog, obj);
            return obj;
        }
        return null;
    }

    /**
     * <187>Oct 13 2019 10:40:08 DC_FACCSW131 SRM/3/SFP_EXCEPTION:OID 1.3.6.1.4.1.2011.5.25.129.2.1.9 Optical module exception, SFP is not certified. (EntityPhysicalIndex=67438606, BaseTrapSeverity=5, BaseTrapProbableCause=136192, BaseTrapEventType=9, EntPhysicalContainedIn=67108873, EntPhysicalName=GigabitEthernet0/0/32, RelativeResource=Interface GigabitEthernet0/0/32 optical module exception, ReasonDescription=It has been observed that a transceiver has been installed that is not certified by Huawei Ethernet Switch. Huawei cannot ensure that it is completely adaptive and will not cause any adverse effects. If it is continued to be used, Huawei is not obligated to provide support to remedy defects or faults arising out of or resulting from installing and using of the non-certified transceiver.)
     */
    private static void parseMsg3(String syslog, JSONObject obj) {
        String[] msg = syslog.split(" SRM/");
        String[] head = msg[0].trim().split(" ");
        obj.put("hostname", head[head.length - 1]);
        obj.put("event_type", "SRM");
        obj.put("log_des", "华为 - 交换机 - SRM");
        String[] content = msg[1].trim().split("/");
        obj.put("event_level", content[0]);
        obj.put("abstract_msg", content[1].split(":")[0]);
        obj.put("message_content", content[1].substring(content[1].indexOf(":")) + 1);
    }

    private static boolean isHwLog3(String syslog) {
        return syslog.contains("SRM/") && syslog.split("/").length >= 2;
    }

    private static Object logParse2(JSONObject obj) {
        obj.put("log_des", "华为 - 交换机 - " + obj.getStr("event_type"));
        return obj;
    }

    /**
     * 格式：<190>Aug 23 2019 10:39:28 DC_FACCSW131 %%6OVER4/4/CAMPNUM_UNCAMP:The compatible number of the 6over4 tunnel module is not compatible.
     */
    private static void parseMsg2(String syslog, JSONObject obj) {
        String[] split = parseHead(syslog, obj);
        obj.put("abstract_msg", split[2].substring(0, split[2].indexOf(":")));
        obj.put("message_content", split[2].substring(split[2].indexOf(":")));
    }

    private static boolean isHwLog2(String syslog) {
        return StringUtil.containsAll(syslog, " %%", "/", ":");
    }

    /**
     * 格式：<190>Aug 23 2019 10:39:28 DC_FACCSW131 %%01INFO/6/SUPPRESS_LOG(l)[4048]:Last message repeated 1 times.(InfoID=1092489232, ModuleName=MSTP, InfoAlias=RECEIVE_MSTITC)
     */
    private static Object logParse1(JSONObject obj) {
        obj.put("log_des", "华为 - 交换机 - " + obj.getStr("event_type"));
        return obj;
    }


    private static boolean isHwLog1(String syslog) {
        return StringUtil.containsAll(syslog, "]:", ")[", " %%", "/") && syslog.split(" %%").length == 2;
    }

    /**
     * 通用解析
     */
    private static void parseMsg1(String syslog, JSONObject obj) {
        String[] split = parseHead(syslog, obj);
        String[] abstractMsg = split[2].split("\\(");
        obj.put("abstract_msg", abstractMsg[0]);
        String procid = abstractMsg[1].split("\\)\\[")[0];
        switch (procid) {
            case "l":
                obj.put("procid", "Log");
                break;
            case "t":
                obj.put("procid", "Trap");
                break;
            case "d":
                obj.put("procid", "Debug");
                break;
            case "s":
                obj.put("procid", "Security log");
                break;
            default:
                obj.put("procid", procid);
        }

        String[] des = abstractMsg[1].split("]:");
        obj.put("count_num", NumberUtil.parseInt(des[0].split("\\)\\[")[1].trim()));
        obj.put("message_content", syslog.split("]:")[1]);
//        obj.put("text", abstractMsg[2].replaceAll("\\)", ""));
    }

    private static String[] parseHead(String syslog, JSONObject obj) {
        String[] msg = syslog.split(" %%");
        String[] split = msg[1].split("/");
        String[] hostname = msg[0].split(" ");
        obj.put("hostname", hostname[hostname.length - 1]);
        obj.put("device_version", split[0].substring(0, 2));
        obj.put("event_type", split[0].substring(2).trim().toLowerCase());
        obj.put("event_level", split[1]);
        return split;
    }

    public static void main(String[] args) {
//        String syslog = "<190>Aug 23 2019 10:39:28 DC_FACCSW131 %%01INFO/6/SUPPRESS_LOG(l)[4048]:Last message repeated 1 times.(InfoID=1092489232, ModuleName=MSTP, InfoAlias=RECEIVE_MSTITC)";
//        String syslog1 = "<190>Aug 23 2019 10:39:28 DC_FACCSW131 %%01ACL6/4/RPC_FAILED:Failed to call synchronization IPC! (ErrorCode= [ULONG])";
        String sys2 = "<18·7>Oct 15 2019 10:40:40 DC_FACCSW131 SRM/3/SFP_EXCEPTION:OID 1.3.6.1.4.1.2011.5.25.129.2.1.9 Optical module exception, SFP is not certified. (EntityPhysicalIndex=67438286, BaseTrapSeverity=5, BaseTrapProbableCause=136192, BaseTrapEventType=9, EntPhysicalContainedIn=67108873, EntPhysicalName=GigabitEthernet0/0/27, RelativeResource=Interface GigabitEthernet0/0/27 optical module exception, ReasonDescription=It has been observed that a transceiver has been installed that is not certified by Huawei Ethernet Switch. Huawei cannot ensure that it is completely adaptive and will not cause any adverse effects. If it is continued to be used, Huawei is not obligated to provide support to remedy defects or faults arising out of or resulting from installing and using of the non-certified transceiver.)";
        JSONObject object = JSONUtil.createObj();
        object.put("syslog", sys2);
        System.out.println(JSONUtil.parseObj(parse(object.toString())).toJSONString(2));
    }
}
