package cn.hba.audit.flume.soc.log.logh3c.safety;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;

/**
 * h3c 操作日志
 *
 * @author wbw
 * @date 2020/1/7 9:52
 */
class H3cOpconf {
    /**
     * 日志
     * -OperateType=running2net-OperateTime=400-OperateState=success-OperateEndTime=792287392; Operation completed.
     *
     * @param bo     内容
     * @param object 对象
     */
    static void disLog(String bo, JSONObject object) {
        if (!StringUtil.containsAll(bo, "OperateType", "OperateTime", "OperateState")) {
            return;
        }
        String result = bo.substring(bo.lastIndexOf(";"));
        object.put("result", result);
        bo = bo.substring(1, bo.lastIndexOf(";"));
        JSONObject boObj = ParseMessageKv.parseMessage8(bo);
        String operateType = boObj.getStr("operate_type");
        object.put("opt_type", operateType);
        switch (operateType) {
            case "running2startup":
                object.put("opt_type_paraphrase", "将运行配置保存为下次启动配置");
                break;
            case "startup2running":
                object.put("opt_type_paraphrase", "将下次启动配置设置为运行配置");
                break;
            case "running2net":
                object.put("opt_type_paraphrase", "将运行配置保存到网络");
                break;
            case "net2running":
                object.put("opt_type_paraphrase", "将网络上的配置文件上传到设备，并作为当前配置运行");
                break;
            case "net2startup":
                object.put("opt_type_paraphrase", "将网络上的配置文件上传到设备，并保存为下次启动配置文件");
                break;
            case "startup2net":
                object.put("opt_type_paraphrase", "将下次启动配置文件保存到网络");
                break;
            default:
                object.put("opt_type_paraphrase", "");
        }

        object.put("opt_time", boObj.getInt("operate_time"));
        object.put("opt_state", boObj.getStr("operate_state"));
        object.put("opt_state_paraphrase", optState(boObj.getStr("operate_state")));
        object.put("opt_end_time", boObj.getLong("OperateEndTime"));
    }

    private static String optState(String str) {
        switch (str) {
            case "InProcess":
                return "正在执行";
            case "success":
                return "执行成功";
            case "InvalidOperation":
                return "无效的操作";
            case "InvalidProtocol":
                return "无效的协议";
            case "InvalidSource":
                return "无效的源文件名";
            case "InvalidDestination":
                return "无效的目的文件名";
            case "InvalidServer":
                return "无效的服务器地址";
            case "DeviceBusy":
                return "设备繁忙";
            case "InvalidDevice":
                return "设备地址无效";
            case "DeviceError":
                return "设备出错";
            case "DeviceNotWritable":
                return "设备不可写";
            case "DeviceFull":
                return "设备的存储空间不足";
            case "FileOpenError":
                return "文件打开出错";
            case "FileTransferError":
                return "文件传输出错";
            case "ChecksumError":
                return "文件校验和错误";
            case "LowMemory":
                return "没有内存";
            case "AuthFailed":
                return "用户验证失败";
            case "TransferTimeout":
                return "传输超时";
            case "UnknownError":
                return "未知原因";
            case "invalidConfig":
                return "无效配置";
            default:
                return "";
        }

    }

}
