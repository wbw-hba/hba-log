package cn.hba.audit.flume.soc.logwyxy;

import cn.hutool.json.JSONObject;

/**
 * @author  lizhi
 * @date  2019/9/18 9:36
 */
class WyxyJsonParse {

    static void dis(JSONObject object, JSONObject obj) {
        disLogMsg1(object, obj);

        if (object.containsKey("leftservicetype")) {
            obj.put("leftservicetype", object.getStr("leftservicetype"));
        }

        disLogMsg2(object, obj);

        if (object.containsKey("leftid")) {
            obj.put("leftid", object.getStr("leftid"));
        }

        disLogMsg3(object, obj);

        if (object.containsKey("Mac")) {
            obj.put("macid", object.getStr("Mac"));
        }

        if (object.containsKey("Managername")) {
            obj.put("managername", object.getStr("Managername"));
        }

        if (object.containsKey("Logout")) {
            obj.put("logout", object.getStr("Logout"));
        }
        //Timeout	超时
        if (object.containsKey("Update")) {
            obj.put("update", object.getStr("Update"));
        }
        //Change	修改
        if (object.containsKey("Change")) {
            obj.put("change", object.getStr("Change"));
        }
        //Expired	过期
        if (object.containsKey("Expired")) {
            obj.put("expired", object.getStr("Expired"));
        }
        //Locked	锁定
        if (object.containsKey("Locked")) {
            obj.put("locked", object.getStr("Locked"));
        }
        //Timeout	超时
        if (object.containsKey("Timeout")) {
            obj.put("timeout", object.getStr("Timeout"));
        }
        //Cert	证书
        if (object.containsKey("Cert")) {
            obj.put("cert", object.getStr("Cert"));
        }

    }

    private static void disLogMsg3(JSONObject object, JSONObject obj) {
        if (object.containsKey("idtype")) {
            obj.put("idtype", object.getStr("idtype"));
        }
        if (object.containsKey("dhgroup")) {
            obj.put("dhgroup", object.getStr("dhgroup"));
        }

        if (object.containsKey("Ike")) {
            obj.put("ike", object.getStr("Ike"));
        }
        if (object.containsKey("prekey")) {
            obj.put("prekey", object.getStr("prekey"));
        }
        if (object.containsKey("ikelifetime")) {
            obj.put("ikelifetime", object.getStr("ikelifetime"));
        }
        if (object.containsKey("rightdomain")) {
            obj.put("rightdomain", object.getStr("rightdomain"));
        }
        if (object.containsKey("rightaddr")) {
            obj.put("rightaddr", object.getStr("rightaddr"));
        }
        if (object.containsKey("righttype")) {
            obj.put("righttype", object.getStr("righttype"));
        }
        if (object.containsKey("initiator")) {
            obj.put("initiator", object.getStr("initiator"));
        }
        if (object.containsKey("dpdaction")) {
            obj.put("dpdaction", object.getStr("dpdaction"));
        }
        if (object.containsKey("dpdtimeout")) {
            obj.put("dpdtimeout", object.getStr("dpdtimeout"));
        }
        if (object.containsKey("dpddelay")) {
            obj.put("dpddelay", object.getStr("dpddelay"));
        }
        if (object.containsKey("Ipseclifetime")) {
            obj.put("ipseclifetime", object.getStr("Ipseclifetime"));
        }
        if (object.containsKey("compress")) {
            obj.put("compress", object.getStr("compress"));
        }
        if (object.containsKey("pfs")) {
            obj.put("pfs", object.getStr("pfs"));
        }
        if (object.containsKey("phase2")) {
            obj.put("phase2", object.getStr("phase2"));
        }
        if (object.containsKey("ipsec")) {
            obj.put("ipsec", object.getStr("ipsec"));
        }
        if (object.containsKey("phase2")) {
            obj.put("phase2", object.getStr("phase2"));
        }
        if (object.containsKey("Key英文")) {
            obj.put("key_english", object.getStr("Key英文"));
        }
        if (object.containsKey("Restart")) {
            obj.put("restart", object.getStr("Restart"));
        }
        if (object.containsKey("Pwdcomplex")) {
            obj.put("pwdcomplex", object.getStr("Pwdcomplex"));
        }
        if (object.containsKey("Workmode")) {
            obj.put("workmode", object.getStr("Workmode"));
        }

        if (object.containsKey("Info")) {
            obj.put("info", object.getStr("Info"));
        }
    }

    private static void disLogMsg2(JSONObject object, JSONObject obj) {
        if (object.containsKey("leftsubnet")) {
            obj.put("leftsubnet", object.getStr("leftsubnet"));
        }

        if (object.containsKey("subnettype")) {
            obj.put("subnettype", object.getStr("subnettype"));
        }

        if (object.containsKey("leftprotoport")) {
            obj.put("leftprotoport", object.getStr("leftprotoport"));
        }

        if (object.containsKey("leftservice")) {
            obj.put("leftservice", object.getStr("leftservice"));
        }

        if (object.containsKey("ikename")) {
            obj.put("ikename", object.getStr("ikename"));
        }

        if (object.containsKey("interface_name")) {
            obj.put("interface_name", object.getStr("interface_name"));
        }

        if (object.containsKey("ipsecactive")) {
            obj.put("ipsecactive", object.getStr("ipsecactive"));
        }

        if (object.containsKey("dhcpdevice")) {
            obj.put("dhcpdevice", object.getStr("dhcpdevice"));
        }

        if (object.containsKey("dhcpipaddr")) {
            obj.put("dhcpipaddr", object.getStr("dhcpipaddr"));
        }

        if (object.containsKey("dhcpactive")) {
            obj.put("dhcpactive", object.getStr("dhcpactive"));
        }

        if (object.containsKey("tunnels")) {
            obj.put("tunnels", object.getStr("tunnels"));
        }

        if (object.containsKey("rulename")) {
            obj.put("rulename", object.getStr("rulename"));
        }

        if (object.containsKey("xauth")) {
            obj.put("xauth", object.getStr("xauth"));
        }

        if (object.containsKey("rightkeyname")) {
            obj.put("rightkeyname", object.getStr("rightkeyname"));
        }

        if (object.containsKey("leftkeyname")) {
            obj.put("leftkeyname", object.getStr("leftkeyname"));
        }

        if (object.containsKey("rightcert")) {
            obj.put("rightcert", object.getStr("rightcert"));
        }

        if (object.containsKey("leftcert")) {
            obj.put("leftcert", object.getStr("leftcert"));
        }

        if (object.containsKey("endtype")) {
            obj.put("endtype", object.getStr("endtype"));
        }

        if (object.containsKey("rightid")) {
            obj.put("rightid", object.getStr("rightid"));
        }
    }

    private static void disLogMsg1(JSONObject object, JSONObject obj) {
        //mask	掩码
        if (object.containsKey("mask")) {
            obj.put("mask", object.getStr("mask"));
        }
        //external_interface	外部接口
        if (object.containsKey("external_interface")) {
            obj.put("external_interface", object.getStr("external_interface"));
        }
        //Internal_interface	内部接口
        if (object.containsKey("Internal_interface")) {
            obj.put("internal_interface", object.getStr("Internal_interface"));
        }
        //interval	间隔
        if (object.containsKey("interval")) {
            obj.put("interval", object.getStr("interval"));
        }
        //pri	优先级
        if (object.containsKey("pri")) {
            obj.put("priority", object.getStr("pri"));
        }
        //dname	设备名
        if (object.containsKey("dname")) {
            obj.put("app_name", object.getStr("dname"));
        }
        //date	日期
        if (object.containsKey("date")) {
            obj.put("event_time", object.getStr("date"));
        }
        //import	设备标识
        if (object.containsKey("devid")) {
            obj.put("device_uuid", object.getStr("devid"));
        }
        //import	记录日志
        if (object.containsKey("fwlog")) {
            obj.put("fwlog", object.getStr("fwlog"));
        }

        if (object.containsKey("rightservice")) {
            obj.put("rightservice", object.getStr("rightservice"));
        }

        if (object.containsKey("rightprotoport")) {
            obj.put("rightprotoport", object.getStr("rightprotoport"));
        }

        if (object.containsKey("rightsubnet")) {
            obj.put("rightsubnet", object.getStr("rightsubnet"));
        }

        if (object.containsKey("righservicetype")) {
            obj.put("righservicetype", object.getStr("righservicetype"));
        }
    }
}
