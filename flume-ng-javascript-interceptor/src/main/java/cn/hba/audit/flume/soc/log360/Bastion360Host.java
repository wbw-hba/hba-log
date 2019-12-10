package cn.hba.audit.flume.soc.log360;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 解析360的防火墙和VPN
 *
 * @author lizhi
 * @date 2019/9/16 9:16
 */
public class Bastion360Host {

    static Object select(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        // ssl vpn
        if (syslog.split("\\|").length >= 7) {
            obj = vpnParse(syslog);
        } else {
            obj = parse(syslog);
        }
        obj.put("manufacturers_name", "360");

        return obj;
    }

    public static JSONObject parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body.substring(body.indexOf("{")));
        JSONObject obj1 = new JSONObject();
        obj1.put("event_type", "system");
        obj1.put("log_type", "fw");
        obj1.put("log_des", "360-防火墙");
        if (StrUtil.isNotEmpty(obj.getStr("version"))) {
            obj1.put("device_version", obj.getStr("version"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("log_name"))) {
            obj1.put("event_type", obj.getStr("log_name"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("log_id"))) {
            obj1.put("procid", obj.getStr("log_id"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("create_time"))) {
            obj1.put("event_time", obj.getStr("create_time"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("ip"))) {
            obj1.put("source_ip", obj.getStr("ip"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("report_ip"))) {
            obj1.put("original_source_ip", obj.getStr("report_ip"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("mac"))) {
            obj1.put("source_mac", obj.getStr("mac"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("gid"))) {
            obj1.put("gid", obj.getStr("gid"));
        }
        if (StrUtil.isNotEmpty(obj.getStr("work_group"))) {
            obj1.put("domain", obj.getStr("work_group"));
        }
        if (!JSONUtil.isNull(obj.getJSONObject("content"))) {
            JSONObject jsonObject = obj.getJSONObject("content");
            if (StrUtil.isNotEmpty(jsonObject.getStr("mid"))) {
                obj1.put("device_uuid", jsonObject.getStr("mid"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("gid"))) {
                obj1.put("gid", jsonObject.getStr("gid"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("score"))) {
                obj1.put("score", jsonObject.getStr("score"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("event_time"))) {
                obj1.put("modify_time", jsonObject.getStr("event_time"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("create_time"))) {
                obj1.put("start_time", jsonObject.getStr("create_time"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("report_ip"))) {
                obj1.put("original_source_ip", jsonObject.getStr("report_ip"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("name"))) {
                obj1.put("loophole_name", jsonObject.getStr("name"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("type"))) {
                obj1.put("loophole_type", jsonObject.getStr("type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("action")) || StrUtil.isNotEmpty(jsonObject.getStr("desc"))) {
                obj1.put("modify_type", StrUtil.isNotEmpty(jsonObject.getStr("action")) ? jsonObject.getStr("action") : jsonObject.getStr("desc"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("company"))) {
                obj1.put("company", jsonObject.getStr("company"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("opt"))) {
                obj1.put("result", jsonObject.getStr("opt"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("op"))) {
                obj1.put("act", jsonObject.getStr("op"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("detail"))) {
                obj1.put("message_content", jsonObject.getStr("detail"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("virus_path"))) {
                obj1.put("virus_path", jsonObject.getStr("virus_path"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("task"))) {
                obj1.put("admin_name", jsonObject.getStr("task"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("inoutnet"))) {
                obj1.put("inoutnet", jsonObject.getStr("inoutnet"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("device"))) {
                obj1.put("out_device", jsonObject.getStr("device"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("mode"))) {
                obj1.put("out_type", jsonObject.getStr("mode"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("hash_code"))) {
                obj1.put("md5_value", jsonObject.getStr("hash_code"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("patch"))) {
                obj1.put("virus_path", jsonObject.getStr("patch"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("internet_ip"))) {
                obj1.put("internet_ip", jsonObject.getStr("internet_ip"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("believe"))) {
                obj1.put("believe", jsonObject.getStr("believe"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("vpn"))) {
                obj1.put("vpn", jsonObject.getStr("vpn"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("device_type"))) {
                obj1.put("loophole_type", jsonObject.getStr("device_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("device_name"))) {
                obj1.put("app_name", jsonObject.getStr("device_name"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("oper_type"))) {
                obj1.put("opt_type", jsonObject.getStr("oper_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("cfg_type"))) {
                obj1.put("cfg_type", jsonObject.getStr("cfg_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("operation"))) {
                obj1.put("operation", jsonObject.getStr("operation"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("account"))) {
                obj1.put("account", jsonObject.getStr("account"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("account_type"))) {
                obj1.put("account_type", jsonObject.getStr("account_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("source_device"))) {
                obj1.put("source_device", jsonObject.getStr("source_device"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("update_file"))) {
                obj1.put("update_file_time", jsonObject.getStr("update_file"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("access_time"))) {
                obj1.put("access_file_time", jsonObject.getStr("access_time"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("destination_device"))) {
                obj1.put("destination_device", jsonObject.getStr("destination_device"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("destination_file"))) {
                obj1.put("destination_file", jsonObject.getStr("destination_file"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("source_file"))) {
                obj1.put("source_file", jsonObject.getStr("source_file"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("process_name"))) {
                obj1.put("loophole_name", jsonObject.getStr("process_name"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("create_file"))) {
                obj1.put("create_file_time", jsonObject.getStr("create_file"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("md5_file"))) {
                obj1.put("md5_value", jsonObject.getStr("md5_file"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("print_content"))) {
                obj1.put("message_content", jsonObject.getStr("print_content"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("file_path"))) {
                obj1.put("virus_path", jsonObject.getStr("file_path"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("paper_type"))) {
                obj1.put("paper_type", jsonObject.getStr("paper_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("printer_type"))) {
                obj1.put("printer_type", jsonObject.getStr("printer_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("number_copies"))) {
                obj1.put("number_copies", jsonObject.getStr("number_copies"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("number_pages"))) {
                obj1.put("number_pages", jsonObject.getStr("number_pages"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("printer"))) {
                obj1.put("printer_name", jsonObject.getStr("printer"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("content"))) {
                obj1.put("content", jsonObject.getStr("content"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("sender"))) {
                obj1.put("sender", jsonObject.getStr("sender"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("recipient"))) {
                obj1.put("recipient", jsonObject.getStr("recipient"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("title"))) {
                obj1.put("title", jsonObject.getStr("title"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("content_type"))) {
                obj1.put("content_type", jsonObject.getStr("content_type"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("attachments"))) {
                obj1.put("attachments", jsonObject.getStr("attachments"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("starttime"))) {
                obj1.put("start_time", jsonObject.getStr("starttime"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("process_id"))) {
                obj1.put("process_id", jsonObject.getStr("process_id"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("endtime"))) {
                obj1.put("end_Time", jsonObject.getStr("endtime"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("client_id"))) {
                obj1.put("loophole_type", jsonObject.getStr("client_id"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("computer_name"))) {
                obj1.put("loophole_name", jsonObject.getStr("computer_name"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("usb_number"))) {
                obj1.put("facility", jsonObject.getStr("usb_number"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("usb_name"))) {
                obj1.put("app_name", jsonObject.getStr("usb_name"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("udisk_id"))) {
                obj1.put("udisk_id", jsonObject.getStr("udisk_id"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("process_md5"))) {
                obj1.put("md5_value", jsonObject.getStr("process_md5"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("process_path"))) {
                obj1.put("virus_path", jsonObject.getStr("process_path"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("url"))) {
                obj1.put("process_url", jsonObject.getStr("url"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("process_cmdline"))) {
                obj1.put("process_cmdline", jsonObject.getStr("process_cmdline"));
            }
            if (StrUtil.isNotEmpty(jsonObject.getStr("destination_ip"))) {
                obj1.put("destination_ip", jsonObject.getStr("destination_ip"));
            }
        }
        return obj1;
    }

    private static JSONObject vpnParse(String syslog) {
        JSONObject obj = new JSONObject();
        String[] split = syslog.split(" ");
        //日志生成时间
        obj.put("log_des", "360-VPN");
//        obj.put("event_time", split[0] + " " + split[1]);
        //VPN网关名字
        obj.put("app_name", split[2]);
        String[] split1 = syslog.split("\\|");
        //日志等级
        obj.put("event_level", split1[1]);
        //MsgID
        obj.put("procid", split1[2]);
        //Type
        obj.put("event_type", split1[3]);
        //SubType
        obj.put("act", split1[4]);
        obj.put("admin_name", split1[5]);
        obj.put("result", split1[6]);
        obj.put("message_content", split1[7]);
        obj.put("log_type", "vpn");
        return obj;
    }


    public static void main(String[] args) {

        String syslog = "20150304 15:28:14 SecSSL3600 |5|0x02000465|用户|Login|user1|成功|管理员[user1:本地认证服务器]登陆系统:IP[192.168.100.1], 接口[GE1], 登陆方式[HTTPS],认证服务器为[本地认证服务器], 认证类型[LOCAL].";
        syslog = "<6>{\"version\":\"\\u5929\\u64ce6.3.0.8300\",\"log_name\":\"\\u7cfb\\u7edf\\u4fee\\u590d\",\"log_id\":\"b85394e7eb68aeccc38f93851ecd38c5\",\"create_time\":\"2019-10-22 16:02:32\",\"ip\":\"2.74.24.21\",\"report_ip\":\"2.74.24.21\",\"mac\":\"54ab3ae23739\",\"gid\":1,\"work_group\":\"\",\"content\":{\"name\":\"IE\\u9ed8\\u8ba4\\u641c\\u7d22\\u5f15\\u64ce\\u914d\\u7f6e\\u88ab\\u4fee\\u6539\",\"op\":0,\"desc\":\"IE\\u9ed8\\u8ba4\\u7684\\u641c\\u7d22\\u5f15\\u64ce\\uff0c\\u53ef\\u80fd\\u4f1a\\u88ab\\u6728\\u9a6c\\u6240\\u5229\\u7528\\uff0c\\u5bfc\\u81f4\\u641c\\u7d22\\u5f15\\u64ce\\u65e0\\u6cd5\\u66f4\\u6539\\u3002\\u5982\\u679c\\u4e0d\\u662f\\u4f60\\u81ea\\u5df1\\u4fee\\u6539\\uff0c\\u5efa\\u8bae\\u7acb\\u5373\\u4fee\\u590d\\u3002\",\"company\":\"\\u672a\\u77e5\"}}\n";
//        Object object = vpnParse(syslog);
//        JSONObject obj = JSONUtil.parseObj(object);
//        System.out.println(obj.toJSONString(2));
        JSONObject obj = new JSONObject();
        obj.put("syslog",syslog);

        System.out.println(JSONUtil.parseObj(select(obj.toString())).toJSONString(2));
    }

}
