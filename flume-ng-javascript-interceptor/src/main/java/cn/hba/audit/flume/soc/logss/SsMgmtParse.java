package cn.hba.audit.flume.soc.logss;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;

/**
 * 山石管理
 *
 * @author lizhi
 * @date 2019/9/12 9:59
 */
public class SsMgmtParse {

    static void mgmtSyslog(String syslog, JSONObject obj) {
        String eventLogInfoId = obj.getStr("news_id");
        switch ("0x" + eventLogInfoId) {
            case "0x420c0a01":
                obj.put("message_content_explain", "系统被管理员名称从{WebUI | Telnet | SSH | Console}重启。");
                break;
            case "0x420c0a02":
                obj.put("message_content_explain", "系统被管理员名称从{Console | Telnet | SSH | HTTP | HTTPS}关机。");
                break;
            case "0x420c040b":
                obj.put("message_content_explain", "管理员管理员名称通过{Console | Telnet | SSH | HTTP | HTTPS}从 IP 地址登录。");
                break;
            case "0x420c0403":
                obj.put("message_content_explain", "管理员管理员名称尝试通过{Console | Telnet | SSH | HTTP | HTTPS}从 IP 地址登录失败。");
                break;
            case "0x42400506":
                obj.put("message_content_explain", "NETCONF WebService 请求超过最大用户数最大值。");
                break;
            case "0x42400507":
                obj.put("message_content_explain", "与云服务器云服务器名称连接成功。");
                break;
            case "0x42400508":
                obj.put("message_content_explain", "与云服务器云服务器名称断开连接。");
                break;
            case "0x42400a09":
                obj.put("message_content_explain", "绑定网络服务监听套接字失败（端口：999），原因。");
                break;
            case "0x420c0404":
                obj.put("message_content_explain", "请求被拒绝，方法请求方法，URI URI，来自于 IP address。");
                break;
            case "0x420c0705":
                obj.put("message_content_explain", "尝试读取 POST 数据次数次失败。");
                break;
            case "0x420c0706":
                obj.put("message_content_explain", "SSL 尝试写数据次数次失败。共写字节数字节，错误号错误号。");
                break;
            case "0x420c0407":
                obj.put("message_content_explain", "HTTP 端口改变为端口号。");
                break;
            case "0x420c0408":
                obj.put("message_content_explain", "HTTPS 端口改变为端口号。");
                break;
            case "0x420c0409":
                obj.put("message_content_explain", "HTTPS 信任域改变为信任域名称。");
                break;
            case "0x420c040c":
                obj.put("message_content_explain", "来自于 IP address 的连接数超过上限，关闭它。");
                break;
            case "0x420c040a":
                obj.put("message_content_explain", "管理员管理员名称通过{Console | Telnet | SSH | HTTP | HTTPS}从 IP address 退出。");
                break;
            case "0x420c040f":
                obj.put("message_content_explain", "管理员管理员名称使用{Console | Telnet | SSH | HTTP | HTTPS}登录，从 IP 地址：端口号到目的 IP 地址：目的端口号（协议）。");
                break;
            case "0x420c0410":
                obj.put("message_content_explain", "管理员管理员名称使用{Console | Telnet | SSH | HTTP | HTTPS}登录失败，从 源 IP 地址：端口号到目的 IP 地址：端口号(协议)。");
                break;
            case "0x42340401":
                obj.put("message_content_explain", "管理员管理员名称删除了日志类型日志。");
                break;
            case "0x42340402":
                obj.put("message_content_explain", "当前 USB 存储已超过 75%，请备份并删除较老的日志文件以释放空间。");
                break;
            case "0x42340403":
                obj.put("message_content_explain", "当前 USB 存储已超过 90%，请备份并删除较老的日志文件以释放空间。");
                break;
            case "0x42340604":
                obj.put("message_content_explain", "开启 track 日志服务器日志服务器名称，监测对象监测对象名称。");
                break;
            case "0x42340605":
                obj.put("message_content_explain", "关闭 track 日志服务器日志服务器名称，监测对象监测对象名称。");
                break;
            case "0x42340606":
                obj.put("message_content_explain", "日志服务器 track 成功。");
                break;
            case "0x42340407":
                obj.put("message_content_explain", "日志服务器 track 失败。");
                break;
            case "0x42340408":
                obj.put("message_content_explain", "日志类型日志数量超过阈值的百分之九十。");
                break;
            case "0x421c0401":
                obj.put("message_content_explain", "管理员管理员名称在{Console | Telnet | SSH | HTTP | HTTPS}登录，其 IP 地址是 IP address。");
                break;
            case "0x421c0402":
                obj.put("message_content_explain", "管理员管理员名称在{Console | Telnet | SSH | HTTP | HTTPS}登录失败，其 IP 地址是 IP address。");
                break;
            case "0x421c0403":
                obj.put("message_content_explain", "管理员管理员名称在{Console | Telnet | SSH | HTTP | HTTPS}登出，其 IP 地址是 IP address。");
                break;
            case "0x421c0c04":
                obj.put("message_content_explain", "管理员管理员名称登录 SCM-20 卡（槽位槽位号）。");
                break;
            case "0x421c0c05":
                obj.put("message_content_explain", "管理员管理员名称退出 SCM-20 卡（槽位槽位号）。");
                break;
            case "0x421c0406":
                obj.put("message_content_explain", "从 CPU(槽槽位号)发送从'login'信息至主控 CPU(槽槽位号)。)");
                break;
            case "0x421c0407":
                obj.put("message_content_explain", "管理员管理员名称在{Console | Telnet | SSH | HTTP | HTTPS}登录，从源 IP地址：端口号到目的 IP 地址：端口号(协议)。");
                break;
            case "0x421c0408":
                obj.put("message_content_explain", "管理员管理员名称在{Console | Telnet | SSH | HTTP | HTTPS}登录失败，从源IP 地址：端口号到目的 IP 地址：端口号(协议)。");
                break;
            case "0x42140301":
                obj.put("message_content_explain", "保存配置文件到目的地失败，原因是原因。");
                break;
            case "0x42140602":
                obj.put("message_content_explain", "通过目的地保存配置文件成功。");
                break;
            case "0x42142604":
                obj.put("message_content_explain", "”管理员名称” @ {CLI | WebUI | SNMP | … }， 数据类型名称， {add | set | delete | unset | move | …} 实例名称.");
                break;
            case "0x42140e05":
                obj.put("message_content_explain", "虚拟系统名称的配置配置名称被管理员名称删除。");
                break;
            case "0x42140e06":
                obj.put("message_content_explain", "虚拟系统名称的配置配置名称被管理员名称回滚。");
                break;
            case "0x42140e07":
                obj.put("message_content_explain", "虚拟系统名称的配置配置名称被管理员名称导入。");
                break;
            case "0x42142608":
                obj.put("message_content_explain", "\\”用户名\\”@{CLI | WebUI | SNMP | … }, \\”{debug | undebug } 功能名称/ 模块名称\\” 插槽:插槽号， 虚拟系统虚拟系统名称。");
                break;
            case "0x42152609":
                obj.put("message_content_explain", "操作日志: 用户用户名 ：执行操作命令行。");
                break;
            case "0x410c0201":
                obj.put("message_content_explain", "进程进程名称失去心跳。");
                break;
            case "0x410c0d02":
                obj.put("message_content_explain", "Flow 名称正忙。");
                break;
            case "0x410c0a03":
                obj.put("message_content_explain", "系统进入自动恢复，设备重置。");
                break;
            case "0x410c0a04":
                if (syslog.contains("switched")) {
                    obj.put("message_content_explain", "用户用户名将系统固件固件名称切换为启动系统固件失败，切换方式为{WebUI | Telnet | SSH | Console}。");
                } else {
                    obj.put("message_content_explain", "从{WebUI | Telnet | SSH | Console}用系统固件名称升级系统固件。");
                }
                break;
            case "0x413c0a01":
                obj.put("message_content_explain", "用户用户名升级系统固件固件名称成功，升级方式为{WebUI | Telnet | SSH | Console}。");
                break;
            case "0x413c0a02":
                obj.put("message_content_explain", "用户用户名升级系统固件固件名称失败，升级方式为“{WebUI | Telnet | SSH | Console}”。");
                break;
            case "0x413c0a03":
                obj.put("message_content_explain", "用户用户名将系统固件固件名称切换为启动系统固件成功，切换方式为{WebUI | Telnet | SSH | Console}。");
                break;
            case "0x410c0205":
                obj.put("message_content_explain", "发送技术支持邮件成功。");
                break;
            case "0x410c0206":
                obj.put("message_content_explain", "发送技术支持邮件失败。");
                break;
            case "0x410c0a07":
                obj.put("message_content_explain", "设备上次被硬件看门狗复位重起。");
                break;
            case "0x410c0a08":
                obj.put("message_content_explain", "模块名（描述）的硬件看门狗超时。");
                break;
            case "0x410c0a09":
                obj.put("message_content_explain", "由于系统异常，模块名称 （模块位置）主动切换角色。");
                break;
            case "0x410c0a0a":
                obj.put("message_content_explain", "模块名称 （模块位置）成功切换为主用主控模块。");
                break;
            case "0x410c0a0b":
                obj.put("message_content_explain", "cpu 位置成功切换为主用主控模块。");
                break;
            case "0x410c0a0c":
                obj.put("message_content_explain", "模块名的硬件看门狗超时。");
                break;
            case "0x410c050d":
                obj.put("message_content_explain", "模块名内存使用量持续增长。");
                break;
            case "0x410c050e":
                obj.put("message_content_explain", "模块名内存使用量为使用量,超过了门限值门限值。");
                break;
            case "0x410c050f":
                obj.put("message_content_explain", "模块名内存分配激增。");
                break;
            case "0x410c0210":
                obj.put("message_content_explain", "上传压缩文件到服务器失败。");
                break;
            case "0x410c0211":
                obj.put("message_content_explain", "应用处理模块失去心跳心跳值秒，重启子卡。");
                break;
            case "0x410c0212":
                obj.put("message_content_explain", "应用处理模块失去心跳心跳值秒，没有重启子卡。");
                break;
            case "0x410c0213":
                obj.put("message_content_explain", "应用处理模块不在线不在线时间值秒，重启应用处理模块。");
                break;
            case "0x410c0214":
                obj.put("message_content_explain", "应用处理模块不在线不在线时间值秒，没有重启应用处理模块。");
                break;
            case "0x410c0215":
                obj.put("message_content_explain", "等待应用处理模块在线超时，不重启系统。");
                break;
            case "0x410c0216":
                obj.put("message_content_explain", "等待应用处理模块在线超时，重启系统。");
                break;
            case "0x410c0217":
                obj.put("message_content_explain", "没有同步应用处理模块和基础防火墙模块之间的固件版本。");
                break;
            case "0x410c0a18":
                obj.put("message_content_explain", "应用处理模块会被硬件重启。");
                break;
            case "0x410c0219":
                obj.put("message_content_explain", "应用处理模块丢失心跳 X 秒，重启应用处理模块。");
                break;
            case "0x410c021a":
                obj.put("message_content_explain", "应用处理模块丢失心跳 X 秒，不重启应用处理模块。");
                break;
            case "0x410c021b":
                obj.put("message_content_explain", "应用处理模块丢失心跳 X 秒，重启系统。");
                break;
            case "0x410c021c":
                obj.put("message_content_explain", "系统已经启动。");
                break;
            case "0x42240407":
                obj.put("message_content_explain", "TELNET 服务端口号变为端口号。");
                break;
            case "0x42240408":
                obj.put("message_content_explain", "来自 IP address 的 TELNE 连接尝试失败。");
                break;
            case "0x42080a01":
                obj.put("message_content_explain", "系统被管理员名称从{WebUI | Telnet | SSH | Console}重启。");
                break;
            case "0x42082601":
                obj.put("message_content_explain", "管理员管理员名称执行了命令行。");
                break;
            case "0x42080a02":
                obj.put("message_content_explain", "子卡子卡名称被管理员名称从{WebUI | Telnet | SSH | Console}重启。");
                break;
            case "0x42080a03":
                obj.put("message_content_explain", "子卡子卡名称被管理员名称从{WebUI | Telnet | SSH | Console}重启失败。");
                break;
            case "0x42080a04":
                obj.put("message_content_explain", "子卡名称被管理员名称从{WebUI | Telnet | SSH | Console}重启。");
                break;
            case "0x42080a05":
                obj.put("message_content_explain", "子卡名称被管理员名称从{WebUI | Telnet | SSH | Console}重启失败。");
                break;
            case "0x42080a06":
                obj.put("message_content_explain", "子卡子卡名称被管理员名称从{WebUI | Telnet | SSH | Console}重启。");
                break;
            case "0x42080a07":
                obj.put("message_content_explain", "管理员名称通过{WebUI | Telnet | SSH | Console}将设备恢复为出厂设置。");
                break;
            case "0x42080a08":
                obj.put("message_content_explain", "管理员名称通过{WebUI | Telnet | SSH | Console}回滚系统配置。");
                break;
            case "0x42080a09":
                obj.put("message_content_explain", "管理员名称通过{WebUI | Telnet | SSH | Console}重启系统失败。");
                break;
            case "0x42080a0a":
                obj.put("message_content_explain", "命令命令执行成功。");
                break;
            case "0x42080a0b":
                obj.put("message_content_explain", "命令命令执行失败。");
                break;
            case "0x42080a0c":
                obj.put("message_content_explain", "管理员名称通过{WebUI | Telnet | SSH | Console}关机。");
                break;
            case "0x42080a0d":
                obj.put("message_content_explain", "管理员名称通过{WebUI | Telnet | SSH | Console}保存设备配置。");
                break;
            case "0x42080a0e":
                obj.put("message_content_explain", "数据库数据操作 状态。");
                break;
            case "0x42080a0f":
                obj.put("message_content_explain", "数据库数据文件大小为大小字节。");
                break;
            case "0x42080a10":
                obj.put("message_content_explain", "数据库数据操作失败。");
                break;
            case "0x42280401":
                obj.put("message_content_explain", "SSH 服务端口号变为端口号。");
                break;
            case "0x41100201":
                obj.put("message_content_explain", "风扇已停止！");
                break;
            case "0x41100202":
                obj.put("message_content_explain", "危险！温度已经达到 90 摄氏度。");
                break;
            case "0x41100603":
                obj.put("message_content_explain", "{USB0 | USB1}已经被{插入|拔除|管理关闭}。");
                break;
            case "0x41100604":
                obj.put("message_content_explain", "Core X 在过去一分钟的利用率超过了 80%！");
                break;
            case "0x41140601":
                obj.put("message_content_explain", "升级任务名升级特征库成功。");
                break;
            case "0x41140602":
                obj.put("message_content_explain", "升级任务名升级特征库失败。");
                break;
            case "0x41140203":
                obj.put("message_content_explain", "将特征库从旧版本（old-version）升级到新版本（new-version）失败。");
                break;
            case "0x41140504":
                obj.put("message_content_explain", "job-name 回退特征库至版本 old-version 成功。");
                break;
            case "0x41140205":
                obj.put("message_content_explain", "回退特征库至版本 old-version 失败。");
                break;
            case "0x41140206":
                obj.put("message_content_explain", "特征库升级成功后重启 SSM（槽位槽位号）。");
                break;
            case "0x41140207":
                obj.put("message_content_explain", "APP 特征库在 SSM（槽位槽位号）重启失败。");
                break;
            case "0x41100205":
                obj.put("message_content_explain", "扩展卡名称插入槽位号。");
                break;
            case "0x41100206":
                obj.put("message_content_explain", "扩展卡名称移出槽位号。");
                break;
            case "0x41100207":
                obj.put("message_content_explain", "扩展卡名称（槽位号）进入  online 状态。");
                break;
            case "0x41100208":
                obj.put("message_content_explain", "扩展卡名称（槽位号）离开  online 状态。");
                break;
            case "0x41100209":
                obj.put("message_content_explain", "槽位号不支持扩展卡名称。");
                break;
            case "0x4110020a":
                obj.put("message_content_explain", "使用了无效文件系统的存储设备名将在 1 分钟后被重新格式化。");
                break;
            case "0x4110020b":
                obj.put("message_content_explain", "对存储设备名的重新格式化已经完成。");
                break;
            case "0x4110120c":
                obj.put("message_content_explain", "在过去 N 秒内，监控对象利用率超过了阈值阈值%，并且发生 X 次。");
                break;
            case "0x4110120d":
                obj.put("message_content_explain", "在过去 N 秒内，监控对象平均利用率为 M%，超过了阈值阈值%。");
                break;
            case "0x4110022d":
                obj.put("message_content_explain", "写保护已经打开，尝试挂载存储设备名称失败。");
                break;
            case "0x41100a0f":
                obj.put("message_content_explain", "扩展卡名称被自动重启，卡槽位号。");
                break;
            case "0x41100210":
                obj.put("message_content_explain", "危险！温度(测试点温度, 扩展卡名称, 槽位槽位号)已经达到 X 摄氏度。");
                break;
            case "0x41100211":
                obj.put("message_content_explain", "危险！一个电源模块不够运行 X 块子卡模块，断掉多余子卡电源。");
                break;
            case "0x41100412":
                obj.put("message_content_explain", "IOM-2SM-单模 Bypass 模块型号（槽位槽位号）切换到工作模式工作模式，因为原因。");
                break;
            case "0x41100613":
                obj.put("message_content_explain", "扩展卡名称(slot-X)变为状态状态。");
                break;
            case "0x41100c14":
                obj.put("message_content_explain", "位于槽位槽位号的 CPU 日志记录开始");
                break;
            case "0x41100a15":
                obj.put("message_content_explain", "从 CPU(槽位号槽位号)切换为主并重新记录日志。");
                break;
            case "0x41100a16":
                obj.put("message_content_explain", "最小环境温度(T1)超过 X 度。");
                break;
            default:
                break;
        }
        mgmtSyslog1(syslog, obj);
    }

    private static void mgmtSyslog1(String syslog, JSONObject obj) {
        if (StrUtil.containsIgnoreCase(syslog, "System") && StrUtil.containsIgnoreCase(syslog, "by")) {
            //解析操作
            String[] split = syslog.split("System")[1].split("by");
            obj.put("act", split[0].trim());
        } else if (StrUtil.containsIgnoreCase(syslog, "by") && StrUtil.containsIgnoreCase(syslog, "via")) {
            //解析管理员名字
            String[] split = syslog.split("by")[1].split("via");
            obj.put("admin_name", split[0].trim());
        } else if (StrUtil.containsIgnoreCase(syslog, "via")) {
            //解析管理员名字
            String[] split = syslog.split("via")[1].split("\\.");
            if (StrUtil.containsIgnoreCase(split[0].trim(), "failed")) {
                obj.put("attended_mode", split[0].split("failed")[0].trim());
                obj.put("result", split[0].split("failed")[1].trim());
            } else if (StrUtil.containsIgnoreCase(split[0].trim(), "with")) {
                obj.put("attended_mode", split[0].split("with")[0].trim());
                obj.put("firmware_name", split[0].split("with")[1].split("\\.")[0].trim());
            } else if (StrUtil.containsIgnoreCase(split[0].trim(), "version")) {
                obj.put("access_interface", split[0].split(",")[0]);
                obj.put("old_version", split[0].split("old version is")[0].split(",")[0].trim());
                obj.put("new_version", split[0].split("new version is")[0].split("\\.")[0].trim());
            } else {
                obj.put("attended_mode", split[0].trim());
            }
        }
    }


    public static void main(String[] args) {
        String syslog = "<190>Jul 24 14:39:43 1304415172001433(root) 42142604 Configuration@MGMT: \"hillstone\"@webui, rule: 12->src_subnet: 58.218.194.222, 32, deleted ";
//        String[] split = syslog.split("System")[1].split("by");
//        System.out.println(split[0].trim());
//
//        String[] split1 = syslog.split("by")[1].split("via");
//        System.out.println(split1[0].trim());

//        String[] split = syslog.split("via")[1].split("\\.");
//        System.out.println(split[0].split("failed")[0]);


    }

}
