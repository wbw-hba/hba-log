package cn.hba.audit.flume.soc.log.logkb;


import cn.hba.audit.flume.util.DaTiUtil;
import cn.hba.audit.flume.util.ParseMessageKv;

import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author ztf
 * @date 2019/11/28
 */
class KbParse {

    public static Object parse(Object body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disBody(syslog, obj);
        return obj;
    }

    /**
     * 处理日志
     *
     * @param syslog <133>Dec 04 11:06:39 wangzhaWD charset=UTF-8 type=fileTransfer instanceName=文件接收实例 taskName=dbSyncFileTransfer logLevel=(5) 通知 logType=实例运行 objectName=/copFile/dbSync_file/GB-MH-JCMS1205-WAI_front_storage_1/19237846-19237847.sql.zz-28837209Egj.clob desc=开始接收文件[1610 Byte ][1.572265625 KB ] result=成功 date=2019-12-04 11:06:39.462
     * @param obj
     */
    private static void disBody(String syslog, JSONObject obj) {
        syslog = syslog.split("charset=")[1];
        int i = syslog.indexOf(" ");
        String sysStr = syslog.substring(i + 1);
        JSONObject bodyJson = ParseMessageKv.parseMessage6(sysStr);
        disLogType(bodyJson, obj);
        //所有日志公有字段
        obj.put("event_details", bodyJson.getStr("desc"));
        if (bodyJson.containsKey("result")) {
            obj.put("result", bodyJson.getStr("result"));
        }
        //必备字段
        obj.put("manufacturers_facility", "安全产品");
        obj.put("facility_type", "数据交换");
        if (bodyJson.containsKey("date")) {
            obj.put("event_time", DateUtil.parse(bodyJson.getStr("date")).toString(DaTiUtil.FORMAT));
        }
        obj.put("manufacturers_name", "科博");

    }


    /**
     * 处理不同日志的事件类型属性
     */
    private static void disLogType(JSONObject bodyJson, JSONObject obj) {
        String logType = bodyJson.getStr("type");
        switch (logType) {
            case "fileTransfer":
            case "filesync":
                partLogParam(bodyJson, obj);
                obj.put("abstract_overview", bodyJson.getStr("log_type"));
                obj.put("object_name", bodyJson.getStr("object_name"));
                //必备字段
                obj.put("log_type", "sysrun");
                obj.put("event_type", "file");
                obj.put("log_des", "科博-安全产品-文件");
                break;
            case "systemService":
                obj.put("server_name", bodyJson.getStr("service_name"));
                //必备字段
                obj.put("log_type", "sysrun");
                obj.put("event_type", "server");
                obj.put("log_des", "科博-安全产品-系统服务");
                break;
            case "dbsync":
                partLogParam(bodyJson, obj);
                obj.put("abstract_overview", bodyJson.getStr("log_type"));
                obj.put("object_name", bodyJson.getStr("object_name"));
                if (bodyJson.containsKey("resource_info")){
                    obj.put("resource_info", bodyJson.getStr("resource_info"));
                }
                //必备字段
                obj.put("log_type", "network");
                obj.put("event_type", "database");
                obj.put("log_des", "科博-安全产品-数据库");
                break;
            case "webServiceProxyFileMode":
                partLogParam(bodyJson, obj);
                obj.put("client_ip", bodyJson.getStr("client_ip"));
                obj.put("request", bodyJson.getStr("request"));
                obj.put("response", bodyJson.getStr("response"));
                //必备字段
                obj.put("log_type", "sysrun");
                obj.put("event_type", "server");
                obj.put("log_des", "科博-安全产品-WebService服务");
                break;
            default:
                break;
        }
    }

    /**
     * 部分日志公有属性
     */
    private static void partLogParam(JSONObject bodyJson, JSONObject obj) {
        obj.put("event_name", bodyJson.getStr("instance_name"));
        obj.put("task_name", bodyJson.getStr("task_name"));
        obj.put("log_level", bodyJson.getStr("log_level").substring(1, 2));
    }

}
