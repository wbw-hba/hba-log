package cn.hba.audit.flume.soc.logss;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;

/**
 * 山石 AAA
 *
 * @author lizhi
 * @date 2019/9/12 9:39
 */
class SsAaaParse {

    /**
     * <190>Jul 9 10:25:28 1304415172004234(root) 47040613 Event@AAA: authentication response to LOGIN module for administrator hillstone, and answer is failed, password error.
     * <190>Jul 11 11:22:35 1304415172004335(root) 47040612 Event@AAA: authentication response to LOGIN module for administrator hillstone, and answer is success.
     * <190>Jul 2 16:38:32 1304415172004335(root) 47040611 Event@AAA: receive authentication request from LOGIN module for administrator hillstone.
     */
    static void aaaSyslog(String syslog, JSONObject obj) {
        aaaSyslog1(syslog, obj);
        String eventLogInfoId = obj.getStr("news_id");
        switch ("0x" + eventLogInfoId) {
            case "0x47040601":
                obj.put("message_content_explain", "{增加|删除|编辑}管理员管理员名称{实体|权限|登录类型|密码}失败由于原因。");
                break;
            case "0x47040602":
                obj.put("message_content_explain", "{增加|删除|编辑}管理员管理员名称{实体|权限|登录类型|密码}成功。");
                break;
            case "0x47040603":
                obj.put("message_content_explain", "{增加|删除|编辑}AAA 服务器服务器名称{实体|参数}失败由于原因。");
                break;
            case "0x47040604":
                obj.put("message_content_explain", "{增加|删除|编辑}AAA 服务器服务器名称{实体|参数}成功。");
                break;
            case "0x47040605":
                obj.put("message_content_explain", "用户用户名称认证通过。");
                break;
            case "0x47040606":
                obj.put("message_content_explain", "用户用户名称认证被服务器名称拒绝。");
                break;
            case "0x47040607":
                obj.put("message_content_explain", "{增加|删除}用户组用户组名称成功。");
                break;
            case "0x47040608":
                obj.put("message_content_explain", "{增加|删除}用户组用户组名称错误由于原因。");
                break;
            case "0x47040609":
                obj.put("message_content_explain", "{增加|删除|编辑}角色{实体|描述}角色名称成功。");
                break;
            case "0x4704060a":
                obj.put("message_content_explain", "{增加|删除|编辑}角色角色名称{实体|描述}错误由于原因。");
                break;
            case "0x4704060b":
                obj.put("message_content_explain", "{增加|删除}角色映射规则规则成功。");
                break;
            case "0x4704060c":
                obj.put("message_content_explain", "{增加|删除}角色映射规则规则错误由于原因。");
                break;
            case "0x4704060d":
                obj.put("message_content_explain", "{增加|删除}角色映射规则条目条目成功。");
                break;
            case "0x4704060e":
                obj.put("message_content_explain", "{增加|删除}角色映射规则条目条目错误由于原因。");
                break;
            case "0x4704060f":
                obj.put("message_content_explain", "{增加|删除}角色表达式表达式成功。");
                break;
            case "0x47040610":
                obj.put("message_content_explain", "{增加|删除}角色表达式表达式错误由于原因。");
                break;
            case "0x47040611":
                obj.put("message_content_explain", "从应用名称模块收到管理员管理员名称认证请求。");
                break;
            case "0x47040612":
                obj.put("message_content_explain", "回复应用名称模块管理员管理员名称认证请求，结果：成功。");
                break;
            case "0x47040613":
                obj.put("message_content_explain", "回复应用名称模块管理员管理员名称认证请求，结果：失败，原因。");
                break;
            case "0x47040614":
                obj.put("message_content_explain", "从应用名称模块收到用户用户名称认证请求。");
                break;
            case "0x47040615":
                obj.put("message_content_explain", "回复应用名称模块用户用户名称认证请求，结果：成功。");
                break;
            case "0x47040616":
                obj.put("message_content_explain", "回复应用名称模块用户用户名称认证请求，结果：失败，原因。");
                break;
            case "0x47040617":
                obj.put("message_content_explain", "用户绑定达到最大数最大值，为服务器服务器名称添加 IP 地址->用户名映射失败。");
                break;
            case "0x47040618":
                obj.put("message_content_explain", "用户绑定与服务器服务器名称 1 中的某个绑定冲突，为服务器服务器名称 2 强制添加 IP 地址->用户名映射。");
                break;
            case "0x47040419":
                obj.put("message_content_explain", "回复应用名称模块用户用户名称认证请求，结果：成功。");
                break;
            case "0x4704061a":
                obj.put("message_content_explain", "用户用户名称计费原因。");
                break;
            case "0x4704061b":
                obj.put("message_content_explain", "回复应用名称模块用户用户名称修改 PIN 码，结果：成功。");
                break;
            case "0x4704061c":
                obj.put("message_content_explain", "回复应用名称模块用户用户名称修改 PIN 码，结果：失败，原因。");
                break;
            case "0x4704061d":
                obj.put("message_content_explain", "AAA 监听器监听器名称接收到一条上线消息：类型为消息类型，IP 为 IP 地址，用户为用户名称，附加数据为附加数据。结果为结果。");
                break;
            case "0x4704061e":
                obj.put("message_content_explain", "AAA 监听器监听器名称接收到一条下线消息：类型为消息类型，IP 为 IP 地址，用户为用户名称。结果为结果。");
                break;
            case "0x4704061f":
                obj.put("message_content_explain", "AAA 监听器监听器名称接收到一条异常的消息头部。错误码为错误码。");
                break;
            case "0x47040620":
                obj.put("message_content_explain", "AAA 监听器监听器名称接收到一条异常的消息体：类型为消息类型，IP 为 IP 地址错误码为错误码。");
                break;
            case "0x47040626":
                obj.put("message_content_explain", "AAA 监听器监听器名称删除所有无效用户。");
                break;
            case "0x47040621":
                obj.put("message_content_explain", "{增加|删除|编辑}用户自定义角色角色名称 {实体|描述}失败由于原因。");
                break;
            case "0x47040622":
                obj.put("message_content_explain", "{增加|删除|编辑}用户自定义角色角色名称 {实体|描述}成功。");
                break;
            case "0x47040623":
                obj.put("message_content_explain", "sso radius 用户上线：用户名为用户名称，绑定类型为{ip | mac}。");
                break;
            case "0x47040624":
                obj.put("message_content_explain", "sso radius 用户下线：用户名为用户名称，绑定类型为{ip | mac}。");
                break;
            case "0x47040625":
                obj.put("message_content_explain", "sso radius 用户超时退出：用户名为用户名称，绑定类型为{ip | mac}。");
                break;
            case "0x50040601":
                obj.put("message_content_explain", "ad polling 用户上线：用户名为用户名称，绑定类型为 IP 地址。");
                break;
            case "0x50040602":
                obj.put("message_content_explain", "ad polling 用户下线：用户名为用户名称, 绑定类型为 IP 地址。");
                break;
            case "0x50040603":
                obj.put("message_content_explain", "ad polling 用户超时退出：用户名为用户名称, 绑定类型为 IP 地址。");
                break;
            default:
                break;
        }
    }


    private static void aaaSyslog1(String syslog, JSONObject obj) {
        if (StrUtil.containsIgnoreCase(syslog, "administrator")) {
            //解析操作
            String[] split = syslog.split("administrator");
            if (split[1].contains("{")) {
                obj.put("admin_name", split[1].split("\\{")[0].trim());
            } else if (split[1].contains(", and")) {
                obj.put("admin_name", split[1].split(",")[0].trim());
            } else if (split[0].contains("by")) {

            } else {
                obj.put("admin_name", split[1].split("\\.")[0].trim());
            }
        }
    }

}
