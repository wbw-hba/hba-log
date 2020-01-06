package cn.hba.audit.flume.soc.log.logws;

import cn.hba.audit.flume.util.AttackUtil;
import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author wbw
 * @date 2019/11/28 13:27
 */
class WsAttackLog {

    /**
     * 判断是否为攻击日志
     *
     * @param syslog 原始日志
     * @return flag
     */
    static boolean isAttackLog(String syslog) {
        return StringUtil.containsAll(syslog, "->", "devicename", "url", "method", "args", "attack_field", "rule_id");
    }

    /**
     * 日志格式：
     * <188>Dec  1 18:59:50 SecOS 2019-12-01 18:59:50 WAF: 192.168.100.133:60921->192.168.124.253 dip=192.168.109.98
     * devicename=SecOS url=/ method=GET args= flag_field= block_time=0 http_type= attack_field=2 profile_id=19
     * rule_id=40102 type=Signature Rule severity=0 action=CONTINUE referer= useragent= post= equipment=2 os=8 browser=1 |
     */
    static Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");
        disLog(syslog, object);

        return object;
    }

    /**
     * 处理内容
     */
    private static void disLog(String syslog, JSONObject object) {
        // 头部
        String[] head = syslog.split("devicename=");

        String[] dip = head[0].trim().split("->");
        String[] dd = StrUtil.trim(dip[dip.length - 1]).split(" dip=");
        String[] ds = dd[0].split(":");
        object.put("dest_ip", ds[0]);
        if (ds.length == 2) {
            object.put("dest_port", ds[1]);
        }
        if (dd.length > 1) {
            object.put("real_dest_port", dd[1]);
        }
        String[] sport = dip[0].split(":");
        object.put("port", sport[sport.length - 1]);
        object.put("ip", sport[sport.length - 2]);
        object.put("facility_type", sport[sport.length - 3].substring(sport[sport.length - 3].lastIndexOf(" ") + 1));
        // 中间
        String[] body = ("devicename=" + head[1]).split("action=");
        disLogBody(body[0], object);
        // 末尾
        String[] referer = body[1].split("referer=");
        object.put("process_mode", referer[0].trim());
        String[] useragent = referer[1].split("useragent=");
        object.put("referer", useragent[0].trim());
        String[] post = useragent[1].split("post=");
        object.put("useragent", post[0].trim());
        object.put("post", post[1].substring(0, post[1].lastIndexOf("|")).trim());

        // 必备字段
        AttackUtil.eventSonType(object.getStr("attack_type"), object);
        object.put("event_type", "waf");
        object.put("log_type", "attack");
        object.put("manufacturers_name", "网神");
        object.put("manufacturers_facility", "WEB");
        object.put("facility_type", "系统防护");
        object.put("log_des", "网神 - WAF - 系统防护攻击日志");
    }

    private static void disLogBody(String body, JSONObject obj) {
        JSONObject object = ParseMessageKv.parseMessage5(body);
        // 参数
        obj.put("args", object.getStr("args"));
        // 阻断时间
        obj.put("block_time", object.getStr("block_time"));
        // HTTP or HTTPS服务
        obj.put("protocol_type", object.getStr("http_type"));
        // 规则的ID
        obj.put("rule_id", object.getStr("rule_id"));
        obj.put("rule_id_paraphrase", ruleIdParaphrase(object.getInt("rule_id", 0)).trim());
        // 攻击的严重级别
        obj.put("severity", severity(object.getInt("severity", 1)));
        // HTTP攻击点
        obj.put("attack_field", attackField(object.getInt("attack_field", 1)));

        obj.put("http_method", object.getStr("method"));

        obj.put("profile_id", object.getStr("profile_id"));
        obj.put("protection_object_id", object.getStr("flag_field"));
        obj.put("facility_hostname", object.getStr("devicename"));

        obj.put("attack_type", attackType(object.getStr("type")));
        obj.put("url_path", object.getStr("url"));
        obj.put("conduct_operations", object.getStr("action"));
    }

    /**
     * 规则ID释义
     */
    private static String ruleIdParaphrase(int ruleId) {
        switch (ruleId) {
            case 1000:
                return "引擎处理遇到异常数据引发特殊规则";
            case 1001:
                return "参数中包含有SQL语句的条件关键字，如：where,and,or等";
            case 1002:
                return "参数中包含完整的SQL语句，可能会执行非法的查询语句，导致数据库内容泄漏";
            case 1003:
                return "参数中包含有查询数据库全局变量的SQL语句关键字，如：@version";
            case 1004:
                return "变量转换函数";
            case 1005:
                return "参数中包含数据库扩展过程等关键字";
            case 1006:
                return "参数中包含有SQL语句的变量声明的关键字，可能进行一些诸如批量挂马的恶意操作";
            case 1007:
                return "字符转换函数";
            case 1008:
                return "十六进制编码";
            case 1009:
                return "SSI注入";
            case 1010:
                return "参数中包含一些用于检测是否存在SQL注入的单引号，可能导致数据库查询语句语法错误，暴露数据库的调试信息";
            case 1011:
                return "参数中包含一些用于检测是否存在SQL注入的union关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1012:
                return "参数中包含一些用于检测是否存在SQL注入的group关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1013:
                return "参数中包含一些用于检测是否存在SQL注入的order关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1014:
                return "参数中包含一些用于检测是否存在SQL注入的注释关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1015:
                return "参数中包含一些用于检测是否存在SQL注入的数字逻辑运算关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1016:
                return "参数中包含一些用于检测是否存在SQL注入的having关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1017:
                return "参数中包含一些用于检测是否存在SQL注入的select from关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1018:
                return "参数中包含一些用于检测是否存在SQL注入的insert into关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1019:
                return "参数中包含一些用于检测是否存在SQL注入的create table关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1020:
                return "参数中包含一些用于检测是否存在SQL注入的select count关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1021:
                return "参数中包含一些用于检测是否存在SQL注入的单引号及其各种变形，可能导致数据库查询语句语法错误，暴露数据库的调试信息";
            case 1022:
                return "返回头中包含可能泄漏数据库调试信息的错误头";
            case 1023:
                return "返回内容中包含ODBC错误等调试信息，泄漏数据库和服务器的基本信息";
            case 1024:
                return "参数中包含一些用于检测是否存在SQL语句条件逻辑运算关键字，可能导致数据库查询语句语法错误或转义，暴露数据库的调试信息和数据信息";
            case 1025:
                return "参数中包含完整的Delete语句，可能会执行非法的删除操作，导致数据库内容被篡改";
            case 1026:
                return "存在结束字符串的特殊字符，用于绕过检测系统的检测";
            case 1027:
                return "参数中包含完整的Update语句，可能会执行非法的更新操作，导致数据库内容被篡改";
            case 2000:
                return "参数中包含脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2001:
                return "参数中包含style属性中包含事件触发函数，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2002:
                return "参数中包含execscript属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2003:
                return "参数中包含src属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2004:
                return "参数中包含livescript属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2005:
                return "参数中包含body属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2006:
                return "参数中包含script属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2007:
                return "参数中包含activex属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2008:
                return "参数中包含application属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2009:
                return "参数中包含url属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2010:
                return "参数中包含background属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2011:
                return "参数中包含input属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2012:
                return "参数中包含fromchartcode函数引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2013:
                return "参数中包含exescript属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2014:
                return "参数中包含iframe属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2015:
                return "参数中包含cdata属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2016:
                return "参数中包含meta属性值的脚本引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2017:
                return "参数中包含on系列的事件触发函数，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2018:
                return "参数中包含windows的相关属性的引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2019:
                return "参数中包含windows的相关属性的引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2020:
                return "参数中包含windows的相关属性的引用，这些事件可能是恶意的脚本程序，导致在客户系统中执行恶意的程序";
            case 2021:
                return "参数中包含Html编码符号，可能用于跨站攻击";
            case 2022:
                return "参数中包含UTF-7编码符号，可能用于跨站攻击";
            case 2023:
                return "参数中包含UTF-7编码符号，可能用于跨站攻击";
            case 2024:
                return "MTHML跨域攻击";
            case 2025:
                return "Data属性";
            case 3000:
                return "参数中包含已知安全漏洞的路径信息，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3001:
                return "参数中包含敏感文件的相对路径信息，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3002:
                return "参数中包含敏感文件的相对路径信息，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3003:
                return "参数中包含Base64编码后的特征字符，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3004:
                return "参数中包含单引号，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3005:
                return "Unicode编码转换跨站攻击";
            case 3006:
                return "wvs扫描器正在扫描";
            case 3007:
                return "appscan扫描器正在扫描";
            case 3008:
                return "Http请求头包含扫描器";
            case 3009:
                return "Structs2/XWork攻击";
            case 3010:
                return "unicode单引号";
            case 3011:
                return "unicode跨站";
            case 3012:
                return "unicode路径";
            case 3013 - 3699:
                return "参数中包含已知安全漏洞的路径信息，一般用于扫描器用来探测漏洞的方法，通过这种方式，扫描器可以检查服务器的反馈信息，用以判断是否存在安全隐患";
            case 3700:
                return "wvs扫描器正在扫描";
            case 3701:
                return "Structs2/XWork攻击";
            case 3702:
                return "Unicode编码转换跨站攻击";
            case 3703:
                return "Unicode编码转换跨站攻击";
            case 4000 - 4002:
                return "服务器返回中包含显示目录的特征，导致服务目录的泄漏";
            case 4003:
                return "服务器返回中包含ADODB错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4004:
                return "服务器返回中包含VBScript错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4005:
                return "服务器返回中包含Oracle错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4006:
                return "服务器返回中包含Ole错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4007:
                return "服务器返回中包含Oracle错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4008:
                return "服务器返回中包含ODBC错误的调试信息，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4009:
                return "服务器返回状态号为4XX 5XX，暴露的服务器的敏感信息，可能导致注入攻击";
            case 4010:
                return "页面中包含银行卡信息";
            case 4011:
                return "IIS在实现上存在文件枚举漏洞，攻击者可利用此漏洞枚举网络服务器根目录中的文件";
            case 5000 - 5004:
                return "HTTP请求头中包含谷歌爬虫的特征信息，可能是谷歌爬虫对网站内容进行爬取，启用该规则可以防止网站内容被爬取";
            case 5005 - 5011:
                return "HTTP请求头中包含邮件地址爬虫的特征信息，启用该规则可以防止网站上的邮件地址信息被爬虫收集";
            case 5012:
                return "HTTP请求头中包含非法的Agent信息，启用该规则可以防止网站上的信息被恶意爬虫收集";
            case 5013:
            case 5014:
            case 5015:
            case 5016:
            case 5017:
            case 5018:
            case 5019:
                return "HTTP请求头中包含已知的爬虫工具信息，启用该规则可以防止网站上的信息被恶意爬虫收集";
            case 6000:
                return "HTTP请求中使用了put delete connect options head trace等请求，可能会导致服务器的内容被篡改";
            case 6001:
                return "HTTP请求中使用了恶意的URL编码，可能会导致服务器的崩溃或者信息泄漏";
            case 6002:
                return "HTTP请求头中使用了非法的字符串，可能会导致服务器的崩溃或者信息的泄漏";
            case 6003:
                return "参数中包含非法的字符串，可能会导致服务器的崩溃或者信息的泄漏";
            case 6004:
                return "Post请求中没有Conetent-Length，可能会导致服务器的崩溃或者信息的泄漏";
            case 6005:
                return "GET或者HEAD请求中包含了Body内容";
            case 6006:
                return "Content-Length内容不是数字";
            case 6007:
                return "通过发送多个特制的HTTP请求，导致两个实体攻击看到两个不同的请求套，让黑客没有其他走私意识到它的设备一台设备的请求。";
            case 6008:
                return "HTTP请求方法非法";
            case 6009:
                return "Unicode编码包含畸形的编码，可能导致服务器崩溃或信息泄漏";
            case 6010:
                return "HTTP请求头中包含跨站攻击特征";
            case 6011:
                return "chunked编码方式不允许，可能导致解码错误";
            case 6012 - 6013:
                return "HTTP请求路径非法，可能导致服务器崩溃或信息泄漏";
            case 6014:
                return "HTTP请求Cookie中包含注入特征，可能导致服务器崩溃或信息泄漏";
            case 6015:
                return "HTTP请求头中包含命令执行特征，可能导致服务器崩溃或信息泄漏";
            case 6016:
                return "UserAgent头中包含注入特征，可能导致服务器崩溃或信息泄漏";
            case 6017:
                return "HTTP请求头中包含注入特征，可能导致服务器崩溃或信息泄漏";
            case 6018:
                return "Url中包含命令执行的攻击特征，可能导致服务器崩溃或信息泄漏";
            case 6019:
                return "http请求中包含php恶意函数，可能导致服务信息泄漏";
            case 6020:
                return "Referer中包含命令行攻击函数，可能导致服务器崩溃或信息泄漏";
            case 6021:
                return "HTTP请求中包含远程文件访问函数特征，肯能导致服务器文件泄漏";
            case 6022:
                return "HTTP请求的脚本为恶意程序，可能导致服务器执行恶意程序";
            case 6023:
                return "访问了操作系统的保护文件，如： /etc/passwd等";
            case 6024:
                return "PHP程序的cookie内容包含非法的内容，可能导致服务处理程序崩溃";
            case 6025:
                return "PHP请求不符合策略，可能导致服务处理程序崩溃";
            case 6026:
                return "HTTP字段长度等不符合相关标准，可能导致服务器处理程序崩溃";
            case 7000 - 7003:
                return "恶意文件上传";
            case 7004:
                return "参数中包含命令连接符以及常用系统命令";
            case 7005:
                return "上传内容包含include virtual file等恶意字符，可能是后门文件";
            case 7006:
                return "上传内容包含script runat等恶意字符，可能是后门文件";
            case 7007:
                return "上传内容包含eval request等恶意字符，可能是后门文件";
            case 7008:
                return "上传内容包含execute request等恶意字符，可能是后门文件";
            case 7009:
                return "上传内容包含ExecuteGlobal等恶意字符，可能是后门文件";
            case 7010:
                return "上传内容包含ExeCuteStatement等恶意字符，可能是后门文件";
            case 7011:
                return "上传内容包含codepage 65000等恶意字符，可能是后门文件";
            case 7012:
                return "上传内容包含language script encode等恶意字符，可能是后门文件";
            case 7013:
                return "上传内容包含exec等恶意字符，可能是后门文件";
            case 7014:
                return "上传内容包含ShellExcute等恶意字符，可能是后门文件";
            case 7015:
                return "上传内容包含Execute等恶意字符，可能是后门文件";
            case 7016:
                return "上传内容包含server transfer execute等恶意字符，可能是后门文件";
            case 7017:
                return "上传内容包含TextFile等恶意字符，可能是后门文件";
            case 7018:
                return "上传内容包含runat language script等恶意字符，可能是后门文件";
            case 7019:
                return "上传内容包含language runat script等恶意字符，可能是后门文件";
            case 7020:
                return "上传内容包含language script等恶意字符，可能是后门文件";
            case 7021:
                return "上传内容包含SaveToFile等恶意字符，可能是后门文件";
            case 7022:
                return "上传内容包含SaveAs等恶意字符，可能是后门文件";
            case 7023:
                return "上传内容包含CreateObject等恶意字符，可能是后门文件";
            case 7024:
                return "上传内容包含ADOXCataLog等恶意字符，可能是后门文件";
            case 7025:
                return "上传内容包含script php等恶意字符，可能是后门文件";
            case 7026:
                return "上传内容包含eval http等恶意字符，可能是后门文件";
            case 7027:
                return "上传内容包含cmd.exe等恶意字符，可能是后门文件";
            case 7028:
                return "上传内容包含set_time_limit等恶意字符，可能是后门文件";
            case 7029:
                return "上传内容包含get post cookie request files等恶意字符，可能是后门文件";
            case 7030:
                return "上传内容包含eval等恶意字符，可能是后门文件";
            case 7031:
                return "上传内容包含http等恶意字符，可能是后门文件";
            case 7032:
                return "上传内容包含passthru等恶意字符，可能是后门文件";
            case 7033:
                return "上传内容包含exec等恶意字符，可能是后门文件";
            case 7034:
                return "上传内容包含shell_exec等恶意字符，可能是后门文件";
            case 7035:
                return "上传内容包含popen等恶意字符，可能是后门文件";
            case 7036:
                return "上传内容包含proc_open等恶意字符，可能是后门文件";
            case 7037:
                return "上传内容包含win_shell_execute等恶意字符，可能是后门文件";
            case 7038:
                return "上传内容包含win32_create_service等恶意字符，可能是后门文件";
            case 7039:
                return "上传内容包含win_shell_execute等恶意字符，可能是后门文件";
            case 7040:
                return "上传内容包含include_once等恶意字符，可能是后门文件";
            case 7041:
                return "上传内容包含require等恶意字符，可能是后门文件";
            case 7042:
                return "上传内容包含require_once等恶意字符，可能是后门文件";
            case 7043:
                return "上传内容包含file_put_contents等恶意字符，可能是后门文件";
            case 7045:
                return "上传内容包含fwrite等恶意字符，可能是后门文件";
            case 7046:
                return "上传内容包含fputs等恶意字符，可能是后门文件";
            case 7047:
                return "上传内容包含system等恶意字符，可能是后门文件";
            case 7048:
                return "上传内容包含assert等恶意字符，可能是后门文件";
            case 7049:
                return "上传内容包含preg_replace等恶意字符，可能是后门文件";
            case 7050:
                return "上传内容包含create_function等恶意字符，可能是后门文件";
            case 7051:
                return "上传内容包含unserialize等恶意字符，可能是后门文件";
            case 7052:
                return "上传内容包含call_user_func等恶意字符，可能是后门文件";
            case 7053:
                return "上传内容包含system Diagnostics等恶意字符，可能是后门文件";
            case 7054:
                return "上传内容包含webadmin等恶意字符，可能是后门文件";
            case 7055:
                return "上传内容包含language jscript等恶意字符，可能是后门文件";
            case 7056:
                return "上传内容包含system io等恶意字符，可能是后门文件";
            case 7057:
                return "上传内容包含httppostedfile等恶意字符，可能是后门文件";
            case 7058:
                return "上传内容包含system reflection等恶意字符，可能是后门文件";
            case 7059:
                return "上传内容包含system management等恶意字符，可能是后门文件";
            case 7060:
                return "上传内容包含save等恶意字符，可能是后门文件";
            case 7061:
                return "请求中包含操作系统shell命令，可能是远程执行服务器操作系统命令";
            case 7062:
                return "已知后门程序正在被访问，可能服务器已被安装了后门。";
            case 7063:
                return "已知的php后门程序正在被访问";
            case 7064:
                return "请求中包含已知的rookkit特征信息";
            case 7065:
                return "请求中包含已知的asp rookkit特征信息";
            case 7066:
                return "请求中包含已知的spamtool特征信息，可能系统已被安装了该恶意程序";
            case 7067:
                return "请求中包含php远程溢出攻击的特征，可能造成拒绝服务或者信息泄漏攻击";
            case 7068:
                return "针对已知存在注入漏洞的php程序进行访问，可能造成服务器信息篡改或者泄漏";
            case 7069:
                return "访问中包含traceroute命令，可能是针对服务器系统的命令操作";
            case 7070:
                return "访问系统受保护的文件";
            case 7071:
                return "针对php会话信息的攻击，可能绕过正常的认证机制";
            case 7072:
                return "访问中包含SMTP重定向命令，可能是针对服务器系统的命令操作";
            case 7073:
                return "访问中包含操作系统的命令，可能是针对服务器系统的命令操作";
            case 7074:
                return "访问中包含操作系统命令的注入特征，可能是针对服务器系统的命令操作";
            case 7075:
                return "访问中包含perl命令，可能是针对服务器系统的命令操作";
            case 7076:
                return "访问中包含link命令，可能是针对服务器系统的命令操作";
            case 7077:
                return "访问中包含cd命令，可能是针对服务器系统的命令操作";
            case 7078:
                return "访问中包含访问命令历史的命令，可能是针对服务器系统的命令操作";
            case 7079:
                return "访问中包含php写入和打开文件操作的函数，可能导致服务器文件被篡改";
            case 7080:
                return "针对Tomcat源代码泄漏攻击，可能是针对服务器系统的命令操作";
            case 7081:
                return "存在针对frantpage的路径的攻击";
            case 7082:
                return "存在针对XML-RPC xmlrpc.php进行的攻击";
            case 7083:
                return "存在针对XML-RPC软件进行的注入攻击";
            case 7084:
                return "包含执行generic命令的特征，可能导致在服务器上执行该命令";
            case 7085:
                return "包含执行命令的特征，可能导致在服务器上执行该命令";
            case 7086:
                return "包含执行命令的特征，可能导致在服务器上执行该命令";
            case 7087:
                return "通用的PHP攻击代码";
            case 7088:
                return "php上传文件内容中包含注入攻击命令，可能导致服务器崩溃或信息泄漏";
            case 7089:
                return "HTTP头中包含php的代码，具有注入攻击特征，可能导致服务器崩溃";
            case 7090:
                return "通用蠕虫攻击特征被发现，可能导致网络或服务器负载过大而瘫痪";
            case 7091:
                return "XSS样利用涉及HTML代码masqerading作为头像上传到phpBB的网站板（所有版本- 也许其他Web板太）与运行在预期受害者的Internet Explorer（所有版本）的游客。它可以被用来窃取的Cookie信息和发送到远程位置。";
            case 7092:
                return "http上传图片内容中包含命令执行的特征，可能被用来进行远程执行命令的攻击";
            case 7093:
                return "http上传的图片文件中包含畸形结构的图片，可能被用来进行溢出攻击";
            case 7094:
                return "HTTP请求中包含php打开文件的的函数，可能存在文件写入或者删除攻击，导致网站内容被篡改";
            case 7095:
                return "HTTP请求为恶意文件上传的请求，攻击者正在上传后门管理程序";
            case 7096:
                return "参数中包含命令连接符以及常用系统命令";
            case 7097:
                return "参数中包含命令连接符以及常用系统命令";
            default:
                return "未知";
        }
    }

    /**
     * 严重级别
     */
    private static String severity(int severity) {
        switch (severity) {
            case 1:
                return "次要的";
            case 2:
                return "严重的";
            default:
                return "一般的";
        }
    }

    /**
     * 攻击类型
     */
    private static String attackType(String type) {
        switch (StrUtil.trim(type.toLowerCase())) {
            case "http conformity rule":
                return "HTTP协议校验";
            case "http acl rule":
                return "HTTP访问控制";
            case "signature rule":
                return "特征防护";
            case "crawler rule":
                return "爬虫";
            case "leech rule":
                return "防盗链";
            case "csrf rule":
                return "跨站请求伪造";
            case "upload rule":
                return "文件上传";
            case "download rule":
                return "文件下载";
            case "sensitive info rule":
                return "敏感信息";
            default:
                return "弱密码检测";
        }
    }

    /**
     * HTTP攻击点
     */
    private static String attackField(int field) {
        switch (field) {
            case 0:
                return "REQUEST_HEAD";
            case 1:
                return "REQUEST_BODY";
            case 2:
                return "RESPONSE_HEAD";
            default:
                return "RESPONSE_BODY";
        }
    }
}
