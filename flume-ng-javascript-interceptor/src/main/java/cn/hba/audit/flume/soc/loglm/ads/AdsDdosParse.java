package cn.hba.audit.flume.soc.loglm.ads;

import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.util.Objects;

/**
 * 绿盟抗拒绝服务系统 NSFOCUS ADS V4.5
 * 抗DDOS攻击
 *
 * @author wbw
 * @date 2019/9/10 9:31
 */
public class AdsDdosParse {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");

        if (isAdsAction(syslog)) {
            // 系统操作日志
            adsActionParse(syslog, obj);
        } else if (isAdsLogin(syslog)) {
            // 系统登录日志
            adsLoginParse(syslog, obj);
        } else if (isAdsCpuMem(syslog)) {
            // CPU/MEM信息
            adsCpuMem(syslog, obj);
        } else if (isAdsAttack(syslog)) {
            // 攻击日志
            adsAttack(syslog, obj);
        } else if (isAdsAttackEvent(syslog)) {
            // 攻击事件日志
            adsAttackEvent(syslog, obj);
        } else if (isAdsPortinfo(syslog)) {
            // 接口流量状态日志
            adsPortinfo(syslog, obj);
        } else if (isAdsCollapsar(syslog)){
            adsCollapsar(syslog,obj);
        }else {
            return null;
        }
        obj.put("manufacturers_name", "lm");
        obj.put("log_type", "ads");
        return obj;
    }

    /**
     * 接口流量状态日志
     * <p>
     * 格式： <134>  Portinfo(Port, State, rx Kpps, tx Kpps, rx Mbps, tx Mbps) : 0  T1/1 down 0 0 0 0 | 1  T1/2 down 0 0 0 0
     * | 2  T2/1 down 0 0 0 0 | 3  T2/2 down 0 0 0 0 | 4  G3/1 up 13 14 14 36 | 5  G3/2 down 0 0 0 0
     * | 6  G3/3 down 0 0 0 0 | 7  G3/4 down 0 0 0 0 | 8  G3/5 down 0 0 0 0 | 9  G3/6 down 0 0 0 0 | 10 G3/7 down 0 0 0 0
     * | 11 G3/8 down 0 0 0 0 | 12 F4/1 up 14 13 36 14 | 13 F4/2 down 0 0 0 0 | 14 F4/3 down 0 0 0 0 | 15 F4/4 down 0 0 0 0
     * | 16 F4/5 down 0 0 0 0 | 17 F4/6 down 0 0 0 0 | 18 F4/7 down 0 0 0 0 | 19 F4/8 down 0 0 0 0 |
     */
    private static void adsPortinfo(String syslog, JSONObject obj) {
        obj.put("event_type", "attack_event");
        obj.put("log_des", "绿盟 - ads - 接口流量状态");
        // source_port  status  rx_kpps   tx_kpps   rx_mbps  tx_mbps
        String msg = syslog.substring(syslog.indexOf(":") + 1).trim();
        String[] split = msg.split("\\|");
        for (String ms : split) {
            String[] content = ms.trim().replaceAll(" {2}", " ").split(" ");
            int i = 1;
            String sn = content[0].trim();
            obj.put("source_port_" + sn, content[i++].trim());
            obj.put("status_" + sn, content[i++].trim());
            obj.put("rx_kpps_" + sn, content[i++].trim());
            obj.put("tx_kpps_" + sn, content[i++].trim());
            obj.put("rx_mbps_" + sn, content[i++].trim());
            obj.put("tx_mbps_" + sn, content[i].trim());
        }
    }

    /**
     * 攻击事件日志
     * <p>
     * 格式：<129> attack_event: 2019-08-29 05:58:32|Attack Alert|DstIP=58.218.194.170 DstPort=0 DstPortChanged=0
     * AttackType="UDP Fragment" BeginTime=2019-08-29 05:58:02 EndTime="--"
     * Status=Begin Flow=756437/522 Filter=756437/522|local|admin
     * <p>
     * 格式：<129> attack_event: 2019-08-23 05:58:34|Attack Alert|DstIP=58.218.194.170 DstPort=0 DstPortChanged=0
     * AttackType="UDP Fragment" BeginTime=2019-08-23 05:58:04 EndTime="--"
     * Status=Begin Flow=710347/494 Filter=710347/494|local|admin
     * <p>
     * * 格式：<129> attack_event: 2019-09-25 14:31:19|Attack Alert|DstIP=58.218.194.240 DstPort=4104
     * DstPortChanged=0 AttackType="SYN Flood" BeginTime=2019-09-25 14:30:49 EndTime="--" Status=Begin Flow=476/7 Filter=476/7|local|admin
     */
    private static void adsAttackEvent(String syslog, JSONObject obj) {
        obj.put("event_type", "attack_event");
        obj.put("log_des", "绿盟 - ads - 攻击事件");
        String[] split = syslog.split("\\|");
        int i = 0;
        obj.put("event_time", split[i++].split("attack_event:")[1].trim());
        obj.put("message_content", split[i++]);
        String[] msg = split[i++].split("=");
        int m = 0;
        obj.put("destination_ip", msg[++m].split(" ")[0]);
        obj.put("destination_port", msg[++m].split(" ")[0]);
        obj.put("destination_port_changed", msg[++m].split(" ")[0]);
        obj.put("attack_type", msg[++m].split("\" ")[0].replace("\"", ""));
        obj.put("start_time", msg[++m].split(" EndTime")[0]);
        String end = msg[++m].split(" Status")[0];
        obj.put("end_Time", "\"--\"".equalsIgnoreCase(end) ? "" : end);
        obj.put("status", msg[++m].split(" Flow")[0]);
        obj.put("flow_mes", msg[++m].split(" Filter")[0]);
        obj.put("filter_mes", msg[++m]);
        String ip = split[i++];
        obj.put("source_ip", "local".equalsIgnoreCase(ip) ? "127.0.0.1" : ip);
        obj.put("user_name", split[i]);
    }

    /**
     * 攻击日志
     * <p>
     * 格式：<129> Attack: UDP Flood src=111.194.194.40 dst=58.218.194.222 sport=47695 dport=80 flag=PortRule
     */
    private static void adsAttack(String syslog, JSONObject obj) {
        obj.put("event_type", "attack");
        obj.put("log_des", "绿盟 - ads - 攻击");
        String[] split = syslog.split(" src");
        obj.put("attack_type", split[0].split(": ")[1]);
        String[] msg = split[1].split("=");
        obj.put("source_ip", msg[1].split(" ")[0]);
        obj.put("destination_ip", msg[2].split(" ")[0]);
        obj.put("source_port", msg[3].split(" ")[0]);
        obj.put("destination_port", msg[4].split(" ")[0]);
        obj.put("attack_flag", syslog.split("flag=")[1]);
    }


    /**
     * CPU/MEM信息
     * <p>
     * 格式：<134> Collapsar load: 5% Mem: 76%. SN: Macid:E4DC-3415-1AFF-1B5B Version:V4.5R90F01.sp05 20190508 001
     * <p>
     * 格式：<134> Hardware CPU: 49 C Board: 27 C Fan: 0 SN: 	Macid:E4DC-3415-1AFF-1B5B  Version:V4.5R90F01.sp05 20190508 001
     */
    private static void adsCpuMem(String syslog, JSONObject obj) {
        obj.put("event_type", "cpu");
        obj.put("log_des", "绿盟 - ads - CPU/内存");
        String[] split = syslog.split("%");
        obj.put("cpu_mes", NumberUtil.parseInt(split[0].split("load: ")[1].trim()));
        obj.put("mem_mes", NumberUtil.parseInt(split[1].split("Mem: ")[1].trim()));
        String[] sn = syslog.split("SN:");
        obj.put("sn", sn[1].split("Macid:")[0]);
        obj.put("macid", sn[1].split("Macid:")[1].split("Version:")[0]);
        obj.put("device_version", sn[1].split("Version:")[1]);
    }


    /**
     * 系统登录
     * <p>
     * 格式：<133> Login: admin|********|成功|2.75.160.103|2019-08-04 16:49:19
     */
    private static void adsLoginParse(String syslog, JSONObject obj) {
        obj.put("event_type", "login");
        obj.put("log_des", "绿盟 - ads - 系统登录");
        String[] split = syslog.split("Login: ")[1].split("\\|");
        int i = 0;
        obj.put("user_name", split[i++].trim());
        obj.put("user_pwd", split[i++]);
        obj.put("message_content", split[i++]);
        obj.put("source_ip", split[i++]);
        obj.put("event_time", split[i].trim());
    }

    /**
     * 系统操作日志
     * <p>
     * 格式：<133> Action: 2019-07-10 19:01:49 |HardWare|Recovery CPU: 69 C Board: 46 C Fan: OK|local|admin
     * 格式：<133> Action: 2019-08-02 18:19:46|系统升级|上传升级文件:update_ADS_x86_V4.5R90F01_20181012.zip|2.75.160.105|admin
     * 格式：<133> Action: 2019-08-03 02:34:37|系统基本配置|修改系统基本配置:IP地址:100.73.26.141;网络掩码:255.255.255.0;网关地址:100.73.26.1H口IP配置:;DNS服务器:114.114.114.114;时间服务器:172.17.208.201;Web服务器端口:443;包转发模式:否|2.75.160.105|admin
     * 格式：<133> Action: 2019-08-02 17:30:37|登录安全设置|编辑用户登录安全设置：用户名最小长度:4,密码强度检查:关闭密码生存期检查:不限制,允许登录错误次数:6,登录失败锁定时间:1000秒,IP访问控制状态:不限制,超时自动退出:10分钟;登陆验证码:关闭|2.75.160.105|admin
     */
    private static void adsActionParse(String syslog, JSONObject obj) {
        obj.put("event_type", "action");
        obj.put("log_des", "绿盟 - ads - 系统操作");
        String[] split = syslog.split("Action: ")[1].split("\\|");
        int i = 0;
        obj.put("event_time", split[i++].trim());
        obj.put("opt_pro", split[i++]);
        obj.put("message_content", split[i++]);
        String ip = split[i++];
        obj.put("source_ip", "local".equalsIgnoreCase(ip) ? "127.0.0.1" : ip);
        obj.put("user_name", split[i]);
    }

    /**
     * 硬件信息日志
     * <p>
     * 格式：<134> Hardware CPU: 47 C Board: 25 C Fan: 0 SN: 	Macid:E4DC-3415-1AFF-1B5B  Version:V4.5R90F01.sp05 20190508 001
     */
    private static void adsCollapsar(String syslog, JSONObject obj) {
        obj.put("event_type", "hardware");
        obj.put("log_des", "绿盟 - ads - 硬件信息");
        obj.put("cpu_mes", NumberUtil.parseInt(syslog.split("CPU:")[1].split("C Board")[0].trim()));
        obj.put("board_temperature", NumberUtil.parseInt(syslog.split("C Board:")[1].split("C Fan:")[0].trim()));
        obj.put("fan_status", NumberUtil.parseInt(syslog.split("Fan:")[1].split("SN:")[0].trim()) == 0 ? "正常" : "异常");
        obj.put("sn", syslog.split("SN:")[1].split("Macid:")[0].trim());
        obj.put("macid", syslog.split("Macid:")[1].split(" Version:")[0].trim());
        obj.put("device_version", syslog.split("Version:")[1].trim());
    }

    private static boolean isAdsCollapsar(String syslog) {
        return StringUtil.containsAll(syslog, "Hardware", "CPU", "Macid", "Fan");
    }

    private static boolean isAdsAttackEvent(String syslog) {
        return StringUtil.containsAll(syslog, "attack_event:", "DstIP", "DstPort", "BeginTime", "EndTime", "Status");
    }

    private static boolean isAdsCpuMem(String syslog) {
        return syslog.contains("Collapsar load: ") && syslog.contains("Mem: ")
                && syslog.contains(" Macid:") && syslog.contains("%");
    }

    private static boolean isAdsLogin(String syslog) {
        return syslog.contains("Login: ") && syslog.split("\\|").length == 5;
    }

    private static boolean isAdsAction(String syslog) {
        return syslog.contains("Action:") && syslog.split("\\|").length == 5;
    }

    private static boolean isAdsAttack(String syslog) {
        return syslog.contains("Attack: ") && syslog.contains("src=") && syslog.contains("dst=")
                && syslog.contains("sport=") && syslog.contains("dport=");
    }

    public static boolean isAds(String syslog) {
        return isAdsAction(syslog) || isAdsLogin(syslog) || isAdsCpuMem(syslog) || isAdsAttack(syslog)
                || isAdsAttackEvent(syslog) || isAdsPortinfo(syslog) || isAdsCollapsar(syslog);
    }

    private static boolean isAdsPortinfo(String syslog) {
        return StringUtil.containsAll(syslog, "Portinfo", "Port", "State", "Kpps", "Mbps") && syslog.split("\\|").length > 8;
    }

    public static void main(String[] args) {
        String log = "<134> Hardware CPU: 47 C Board: 25 C Fan: 0 SN: \tMacid:E4DC-3415-1AFF-1B5B  Version:V4.5R90F01.sp05 20190508 001";
//        System.out.println(log.split("\\|").length);
//        log = "<134> Hardware CPU: 49 C Board: 27 C Fan: 0 SN: \tMacid:E4DC-3415-1AFF-1B5B  Version:V4.5R90F01.sp05 20190508 001 ";
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog", log);
        Object parse = parse(obj.toString());
        System.out.println(Objects.requireNonNull(JSONUtil.parse(parse)).toJSONString(2));
    }
}
