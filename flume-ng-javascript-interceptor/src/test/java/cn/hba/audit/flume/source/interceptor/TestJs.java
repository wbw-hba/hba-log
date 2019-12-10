package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.interceptor.IParser;
import cn.hba.audit.flume.interceptor.JsDynamicCompiler;
import cn.hba.audit.flume.interceptor.JsonEventConverter;
import org.apache.flume.event.SimpleEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class TestJs {
    private static final Logger logger = LoggerFactory.getLogger(org.apache.flume.interceptor.StaticInterceptor.class);
    static String scriptContent = "// syslog解析\n" +
            "function parse(headers, body, type) {\n" +
            "    if (type === \"string\") {\n" +
            "        body = JSON.parse(body);\n" +
            "    }\n" +
            "    var resultBody = {};// 返回的结果\n" +
            "    var message = body.syslog;\n" +
            "    // 绿盟 WAF 解析\n" +
            "    if (null !== message && message.indexOf(\"waf\") !== -1) {\n" +
            "\n" +
            "        var priority = body.Priority;\n" +
            "        if (priority) { // 事件等级\n" +
            "            resultBody.event_level = priority;\n" +
            "        }\n" +
            "        var timestamp = message.split(\"stat_time:\")[1].slice(0, \"2019-04-16 17:58:56\".length);\n" +
            "        if (timestamp) { // 事件时间\n" +
            "            resultBody.event_time = timestamp;\n" +
            "        } else {\n" +
            "            resultBody.event_time = new Date();\n" +
            "        }\n" +
            "\n" +
            "        var tag = message.split(\"tag:\")[1].split(\" \")[0];\n" +
            "        var log_type;//日志类型\n" +
            "\n" +
            "        if (tag === \"waf_log_arp\") {\n" +
            "            log_type = \"ARP 防护日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"attack_type:\") !== -1) {\n" +
            "                resultBody.event_attack_type = message.split(\"attack_type:\")[1].slice(0, message.split(\"attack_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_mac:\") !== -1) {\n" +
            "                resultBody.event_src_mac = message.split(\"src_mac:\")[1].slice(0, message.split(\"src_mac:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_mac:\") !== -1) {\n" +
            "                resultBody.event_dst_mac = message.split(\"dst_mac:\")[1].slice(0, message.split(\"dst_mac:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"status:\") !== -1) {\n" +
            "                resultBody.event_status = message.split(\"status:\")[1].slice(0, message.split(\"status:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"action:\") !== -1) {\n" +
            "                resultBody.event_action = message.split(\"action:\")[1].slice(0, message.split(\"action:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"def_ip:\") !== -1) {\n" +
            "                resultBody.event_def_ip = message.split(\"def_ip:\")[1].slice(0, message.split(\"def_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"def_mac:\") !== -1) {\n" +
            "                resultBody.event_def_mac = message.split(\"def_mac:\")[1].slice(0, message.split(\"def_mac:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"conflit_mac:\") !== -1) {\n" +
            "                resultBody.event_conflit_mac = message.split(\"conflit_mac:\")[1].slice(0, message.split(\"conflit_mac:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"count_num:\") !== -1) {\n" +
            "                resultBody.event_count_num = message.split(\"count_num:\")[1].slice(0, message.split(\"count_num:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_login\") {\n" +
            "            log_type = \"登录日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"user:\") !== -1) {\n" +
            "                resultBody.event_user = message.split(\"user:\")[1].slice(0, message.split(\"user:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"password:\") !== -1) {\n" +
            "                resultBody.event_password = message.split(\"password:\")[1].slice(0, message.split(\"password:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"session_id:\") !== -1) {\n" +
            "                resultBody.event_session_id = message.split(\"session_id:\")[1].slice(0, message.split(\"session_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"desc:\") !== -1) {\n" +
            "                resultBody.event_desc = message.split(\"desc:\")[1].slice(0, message.split(\"desc:\")[1].lastIndexOf(\"]\"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"op_type:\") !== -1) {\n" +
            "                resultBody.event_op_type = message.split(\"op_type:\")[1].slice(0, message.split(\"op_type:\")[1].indexOf(\" \"));\n" +
            "                if (resultBody.event_op_type === 0) {\n" +
            "                    resultBody.event_op_type = \"退出\";\n" +
            "                } else {\n" +
            "                    resultBody.event_op_type = \"登陆\";\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"result:\") !== -1) {\n" +
            "                resultBody.event_result = message.split(\"result:\")[1].slice(0, message.split(\"result:\")[1].indexOf(\" \"));\n" +
            "                if (resultBody.event_result === 0) {\n" +
            "                    resultBody.event_result = \"失败\";\n" +
            "                } else {\n" +
            "                    resultBody.event_result = \"成功\";\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_port:\") !== -1) {\n" +
            "                resultBody.event_src_port = message.split(\"src_port:\")[1].slice(0, message.split(\"src_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_op\") {\n" +
            "            log_type = \"操作日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"user:\") !== -1) {\n" +
            "                resultBody.event_user = message.split(\"user:\")[1].slice(0, message.split(\"user:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"session_id:\") !== -1) {\n" +
            "                resultBody.event_session_id = message.split(\"session_id:\")[1].slice(0, message.split(\"session_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"desc:\") !== -1) {\n" +
            "                resultBody.event_desc = message.split(\"desc:\")[1].slice(0, message.split(\"desc:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"op_type:\") !== -1) {\n" +
            "                resultBody.event_op_type = message.split(\"op_type:\")[1].slice(0, message.split(\"op_type:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_op_type) {\n" +
            "                    case 0 :\n" +
            "                        resultBody.event_op_type = \"系统启停\";\n" +
            "                        break;\n" +
            "                    case 1 :\n" +
            "                        resultBody.event_op_type = \"许可证更新\";\n" +
            "                        break;\n" +
            "                    case 2 :\n" +
            "                        resultBody.event_op_type = \"系统升级\";\n" +
            "                        break;\n" +
            "                    case 3 :\n" +
            "                        resultBody.event_op_type = \"系统配置\";\n" +
            "                        break;\n" +
            "                    case 4 :\n" +
            "                        resultBody.event_op_type = \"安全配置\";\n" +
            "                        break;\n" +
            "                    case 5 :\n" +
            "                        resultBody.event_op_type = \"用户管理\";\n" +
            "                        break;\n" +
            "                    case 6 :\n" +
            "                        resultBody.event_op_type = \"日志报表\";\n" +
            "                        break;\n" +
            "                    case 7 :\n" +
            "                        resultBody.event_op_type = \"测试工具\";\n" +
            "                        break;\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"result:\") !== -1) {\n" +
            "                resultBody.event_result = message.split(\"result:\")[1].slice(0, message.split(\"result:\")[1].indexOf(\" \"));\n" +
            "                if (resultBody.event_result === 0) {\n" +
            "                    resultBody.event_result = \"失败\";\n" +
            "                } else {\n" +
            "                    resultBody.event_result = \"成功\";\n" +
            "                }\n" +
            "            }\n" +
            "\n" +
            "        } else if (tag === \"waf_log_system_run\") {\n" +
            "            log_type = \"系统运行日志\";\n" +
            "            if (message.indexOf(\"type:\") !== -1) {\n" +
            "                resultBody.event_type = message.split(\"type:\")[1].slice(0, message.split(\"type:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_type) {\n" +
            "                    case \"System\" :\n" +
            "                        resultBody.event_type = \"开关电源\";\n" +
            "                        break;\n" +
            "                    case \"PM\" :\n" +
            "                        resultBody.event_type = \"服务启停\";\n" +
            "                        break;\n" +
            "                    case \"Database\" :\n" +
            "                        resultBody.event_type = \"数据库启停\";\n" +
            "                        break;\n" +
            "                    case \"Engine\" :\n" +
            "                        resultBody.event_type = \"引擎启停\";\n" +
            "                        break;\n" +
            "                    case \"Web\" :\n" +
            "                        resultBody.event_type = \"Web服务器启停\";\n" +
            "                        break;\n" +
            "                    case \"Link\" :\n" +
            "                        resultBody.event_type = \"以太网口启停\";\n" +
            "                        break;\n" +
            "                    case \"Emergency\" :\n" +
            "                        resultBody.event_type = \"WAF紧急模式\";\n" +
            "                        break;\n" +
            "                    case \"ADS\" :\n" +
            "                        resultBody.event_type = \"ADS联动\";\n" +
            "                        break;\n" +
            "                    case \"DEV_RESOURCE\" :\n" +
            "                        resultBody.event_type = \"设备资源情况\";\n" +
            "                        break;\n" +
            "                    case \"RULE_UPGRADE\" :\n" +
            "                        resultBody.event_type = \"规则升级\";\n" +
            "                        break;\n" +
            "                }\n" +
            "            }\n" +
            "\n" +
            "            if (message.indexOf(\"source:\") !== -1) {\n" +
            "                resultBody.event_source = message.split(\"source:\")[1].slice(0, message.split(\"source:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_source) {\n" +
            "                    case \"interface\" :\n" +
            "                        resultBody.event_source = \"Web界面\";\n" +
            "                        break;\n" +
            "                    case \"system\" :\n" +
            "                        resultBody.event_source = \"Daemon/脚本\";\n" +
            "                        break;\n" +
            "                    case \"engine\" :\n" +
            "                        resultBody.event_source = \"WAF引擎\";\n" +
            "                        break;\n" +
            "                    case \"monitor\" :\n" +
            "                        resultBody.event_source = \"系统监控\";\n" +
            "                        break;\n" +
            "\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"info:\") !== -1) {\n" +
            "                resultBody.event_info = message.split(\"info:\")[1].slice(0, message.split(\"info:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_wafstat\") {\n" +
            "            log_type = \"waf状态日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"cpu:\") !== -1) {\n" +
            "                resultBody.event_cpu = message.split(\"cpu:\")[1].slice(0, message.split(\"cpu:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"mem:\") !== -1) {//内存使用率\n" +
            "                resultBody.event_mem = message.split(\"mem:\")[1].slice(0, message.split(\"mem:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "\n" +
            "        } else if (tag === \"waf_log_l4acl\") {\n" +
            "            log_type = \"网络层访问控制日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_port:\") !== -1) {\n" +
            "                resultBody.event_src_port = message.split(\"src_port:\")[1].slice(0, message.split(\"src_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protocol:\") !== -1) {\n" +
            "                resultBody.event_protocol = message.split(\"protocol:\")[1].slice(0, message.split(\"protocol:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_protocol) {\n" +
            "                    case 0 :\n" +
            "                        resultBody.event_protocol = \"所有\";\n" +
            "                        break;\n" +
            "                    case 1 :\n" +
            "                        resultBody.event_protocol = \"ICMP\";\n" +
            "                        break;\n" +
            "                    case 6 :\n" +
            "                        resultBody.event_protocol = \"TCP\";\n" +
            "                        break;\n" +
            "                    case 17 :\n" +
            "                        resultBody.event_protocol = \"UDP\";\n" +
            "                        break;\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"policy_id:\") !== -1) {\n" +
            "                resultBody.event_policy_id = message.split(\"policy_id:\")[1].slice(0, message.split(\"policy_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"policy_desc:\") !== -1) {\n" +
            "                resultBody.event_policy_desc = message.split(\"policy_desc:\")[1].slice(0, message.split(\"policy_desc:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"action:\") !== -1) {\n" +
            "                resultBody.event_action = message.split(\"protocol:\")[1].slice(0, message.split(\"protocol:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_protocol) {\n" +
            "                    case 1 :\n" +
            "                        resultBody.event_action = \"转发\";\n" +
            "                        break;\n" +
            "                    case 2 :\n" +
            "                        resultBody.event_action = \"阻断\";\n" +
            "                        break;\n" +
            "                    case 3 :\n" +
            "                        resultBody.event_action = \"接受\";\n" +
            "                        break;\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"count_num:\") !== -1) {\n" +
            "                resultBody.event_count_num = message.split(\"count_num:\")[1].slice(0, message.split(\"count_num:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_ddos\") {\n" +
            "            log_type = \"DDos攻击日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "                //switch(resultBody.event_event_type){\n" +
            "                //\tcase \"SYS_FLOOD\" : resultBody.event_event_type=\"Web界面\";break;\n" +
            "                //\tcase \"ACK_FLOOD\" : resultBody.event_event_type=\"Daemon/脚本\";break;\n" +
            "                //\tcase \"HTTP_FLOOD\" : resultBody.event_event_type=\"WAF引擎\";break;\n" +
            "                //\tcase \"Collaboration_Event\" : resultBody.event_event_type=\"系统监控\";break;\n" +
            "                //\tcase \"Slow_Dos\" : resultBody.event_event_type=\"Web界面\";break;\n" +
            "                //}\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"action:\") !== -1) {\n" +
            "                resultBody.event_action = message.split(\"action:\")[1].slice(0, message.split(\"action:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_deface\") {\n" +
            "            log_type = \"防篡改日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"site_id:\") !== -1) {\n" +
            "                resultBody.event_site_id = message.split(\"site_id:\")[1].slice(0, message.split(\"site_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protect_id:\") !== -1) {\n" +
            "                resultBody.event_protect_id = message.split(\"protect_id:\")[1].slice(0, message.split(\"protect_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"url:\") !== -1) {\n" +
            "                resultBody.event_url = message.split(\"url:\")[1].slice(0, message.split(\"url:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"reason:\") !== -1) {\n" +
            "                resultBody.event_reason = message.split(\"reason:\")[1].slice(0, message.split(\"reason:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "\n" +
            "        } else if (tag === \"waf_log_webaccess\") {\n" +
            "            log_type = \"Web访问日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"site_id:\") !== -1) {\n" +
            "                resultBody.event_site_id = message.split(\"site_id:\")[1].slice(0, message.split(\"site_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protect_id:\") !== -1) {\n" +
            "                resultBody.event_protect_id = message.split(\"protect_id:\")[1].slice(0, message.split(\"protect_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"url:\") !== -1) {\n" +
            "                resultBody.event_url = message.split(\"url:\")[1].slice(0, message.split(\"url:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_port:\") !== -1) {\n" +
            "                resultBody.event_src_port = message.split(\"src_port:\")[1].slice(0, message.split(\"src_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"method:\") !== -1) {\n" +
            "                resultBody.event_method = message.split(\"method:\")[1].slice(0, message.split(\"method:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"agent:\") !== -1) {\n" +
            "                resultBody.event_agent = message.split(\"agent:\")[1].slice(0, message.split(\"agent:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"count_num:\") !== -1) {\n" +
            "                resultBody.event_count_num = message.split(\"count_num:\")[1].slice(0, message.split(\"count_num:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"http_protocol:\") !== -1) {\n" +
            "                resultBody.event_http_protocol = message.split(\"http_protocol:\")[1].slice(0, message.split(\"http_protocol:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protocol_tyoe:\") !== -1) {\n" +
            "                resultBody.event_protocol_tyoe = message.split(\"protocol_tyoe:\")[1].slice(0, message.split(\"protocol_tyoe:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wci:\") !== -1) {\n" +
            "                resultBody.event_wci = message.split(\"wci:\")[1].slice(0, message.split(\"wci:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wsi:\") !== -1) {\n" +
            "                resultBody.event_wsi = message.split(\"wsi:\")[1].slice(0, message.split(\"wsi:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"country:\") !== -1) {\n" +
            "                resultBody.event_country = message.split(\"country:\")[1].slice(0, message.split(\"country:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"req_content_type:\") !== -1) {\n" +
            "                resultBody.event_req_content_type = message.split(\"req_content_type:\")[1].slice(0, message.split(\"req_content_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"req_content_len:\") !== -1) {\n" +
            "                resultBody.event_req_content_len = message.split(\"req_content_len:\")[1].slice(0, message.split(\"req_content_len:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"res_content_type:\") !== -1) {\n" +
            "                resultBody.event_res_content_type = message.split(\"res_content_type:\")[1].slice(0, message.split(\"res_content_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"res_content_len:\") !== -1) {\n" +
            "                resultBody.event_res_content_len = message.split(\"res_content_len:\")[1].slice(0, message.split(\"res_content_len:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"waf_status_code:\") !== -1) {\n" +
            "                resultBody.event_waf_status_code = message.split(\"waf_status_code:\")[1].slice(0, message.split(\"waf_status_code:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"ser_status_code:\") !== -1) {\n" +
            "                resultBody.event_ser_status_code = message.split(\"ser_status_code:\")[1].slice(0, message.split(\"ser_status_code:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"correlation_id:\") !== -1) {\n" +
            "                resultBody.event_correlation_id = message.split(\"correlation_id:\")[1].slice(0, message.split(\"correlation_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_session\") {\n" +
            "            log_type = \"会话追踪日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wci:\") !== -1) {\n" +
            "                resultBody.event_wci = message.split(\"wci:\")[1].slice(0, message.split(\"wci:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wsi:\") !== -1) {\n" +
            "                resultBody.event_wsi = message.split(\"wsi:\")[1].slice(0, message.split(\"wsi:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"user_name:\") !== -1) {\n" +
            "                resultBody.event_user_name = message.split(\"user_name:\")[1].slice(0, message.split(\"user_name:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"country:\") !== -1) {\n" +
            "                resultBody.event_country = message.split(\"country:\")[1].slice(0, message.split(\"country:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_websec\") {\n" +
            "            log_type = \"Web安全日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"site_id:\") !== -1) {\n" +
            "                resultBody.event_site_id = message.split(\"site_id:\")[1].slice(0, message.split(\"site_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protect_id:\") !== -1) {\n" +
            "                resultBody.event_protect_id = message.split(\"protect_id:\")[1].slice(0, message.split(\"protect_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_port:\") !== -1) {\n" +
            "                resultBody.event_dst_port = message.split(\"dst_port:\")[1].slice(0, message.split(\"dst_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_port:\") !== -1) {\n" +
            "                resultBody.event_src_port = message.split(\"src_port:\")[1].slice(0, message.split(\"src_port:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"method:\") !== -1) {\n" +
            "                resultBody.event_method = message.split(\"method:\")[1].slice(0, message.split(\"method:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"domain:\") !== -1) {\n" +
            "                resultBody.event_domain = message.split(\"domain:\")[1].slice(0, message.split(\"domain:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"uri:\") !== -1) {\n" +
            "                resultBody.event_uri = message.split(\"uri:\")[1].slice(0, message.split(\"uri:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"policy_id:\") !== -1) {\n" +
            "                resultBody.event_policy_id = message.split(\"policy_id:\")[1].slice(0, message.split(\"policy_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"rule_id:\") !== -1) {\n" +
            "                resultBody.event_rule_id = message.split(\"rule_id:\")[1].slice(0, message.split(\"rule_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"action:\") !== -1) {\n" +
            "                resultBody.event_action = message.split(\"action:\")[1].slice(0, message.split(\"action:\")[1].indexOf(\" \"));\n" +
            "                switch (resultBody.event_action) {\n" +
            "                    case \"Other\" :\n" +
            "                        resultBody.event_action = \"放过\";\n" +
            "                        break;\n" +
            "                    case \"Forward\" :\n" +
            "                        resultBody.event_action = \"放过\";\n" +
            "                        break;\n" +
            "                    case \"Block\" :\n" +
            "                        resultBody.event_action = \"阻断\";\n" +
            "                        break;\n" +
            "                    case \"Accept\" :\n" +
            "                        resultBody.event_action = \"接受\";\n" +
            "                        break;\n" +
            "                    case \"Redirect\" :\n" +
            "                        resultBody.event_action = \"重定向\";\n" +
            "                        break;\n" +
            "                    case \"Pretend\" :\n" +
            "                        resultBody.event_action = \"伪装\";\n" +
            "                        break;\n" +
            "                    case \"Set\" :\n" +
            "                        resultBody.event_action = \"设定\";\n" +
            "                        break;\n" +
            "                    case \"Clear\" :\n" +
            "                        resultBody.event_action = \"清除\";\n" +
            "                        break;\n" +
            "                    case \"Replace\" :\n" +
            "                        resultBody.event_action = \"替换\";\n" +
            "                        break;\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"block:\") !== -1) {\n" +
            "                resultBody.event_block = message.split(\"block:\")[1].slice(0, message.split(\"block:\")[1].indexOf(\" \"));\n" +
            "                if (resultBody.event_block === \"No\") {\n" +
            "                    resultBody.event_block = \"不启用\";\n" +
            "                } else {\n" +
            "                    resultBody.event_block = \"启用\";\n" +
            "                }\n" +
            "            }\n" +
            "            if (message.indexOf(\"block_info:\") !== -1) {\n" +
            "                resultBody.event_block_info = message.split(\"block_info:\")[1].slice(0, message.split(\"block_info:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"http:\") !== -1) {\n" +
            "                resultBody.event_http = message.split(\"http:\")[1].slice(0, message.split(\"http:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"alertinfo:\") !== -1) {\n" +
            "                resultBody.event_alertinfo = message.split(\"alertinfo:\")[1].slice(0, message.split(\"alertinfo:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"proxy_info:\") !== -1) {\n" +
            "                resultBody.event_proxy_info = message.split(\"proxy_info:\")[1].slice(0, message.split(\"proxy_info:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"charaters:\") !== -1) {\n" +
            "                resultBody.event_charaters = message.split(\"charaters:\")[1].slice(0, message.split(\"charaters:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"count_num:\") !== -1) {\n" +
            "                resultBody.event_count_num = message.split(\"count_num:\")[1].slice(0, message.split(\"count_num:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"protocol_type:\") !== -1) {\n" +
            "                resultBody.event_protocol_type = message.split(\"protocol_type:\")[1].slice(0, message.split(\"protocol_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wci:\") !== -1) {\n" +
            "                resultBody.event_wci = message.split(\"wci:\")[1].slice(0, message.split(\"wci:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"wsi:\") !== -1) {\n" +
            "                resultBody.event_wsi = message.split(\"wsi:\")[1].slice(0, message.split(\"wsi:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"country:\") !== -1) {\n" +
            "                resultBody.event_country = message.split(\"country:\")[1].slice(0, message.split(\"country:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"correlation_id:\") !== -1) {\n" +
            "                resultBody.event_correlation_id = message.split(\"correlation_id:\")[1].slice(0, message.split(\"correlation_id:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"site_name:\") !== -1) {\n" +
            "                resultBody.event_site_name = message.split(\"site_name:\")[1].slice(0, message.split(\"site_name:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"vsite_name:\") !== -1) {\n" +
            "                resultBody.event_vsite_name = message.split(\"vsite_name:\")[1].slice(0, message.split(\"vsite_name:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        } else if (tag === \"waf_log_ipblock\") {\n" +
            "            log_type = \"高危IP日志\";\n" +
            "\n" +
            "            if (message.indexOf(\"event_type:\") !== -1) {\n" +
            "                resultBody.event_event_type = message.split(\"event_type:\")[1].slice(0, message.split(\"event_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"alertlevel:\") !== -1) {\n" +
            "                resultBody.event_alertlevel = message.split(\"alertlevel:\")[1].slice(0, message.split(\"alertlevel:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"src_ip:\") !== -1) {\n" +
            "                resultBody.event_src_ip = message.split(\"src_ip:\")[1].slice(0, message.split(\"src_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"dst_ip:\") !== -1) {\n" +
            "                resultBody.event_dst_ip = message.split(\"dst_ip:\")[1].slice(0, message.split(\"dst_ip:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "            if (message.indexOf(\"attack_type:\") !== -1) {\n" +
            "                resultBody.event_attack_type = message.split(\"attack_type:\")[1].slice(0, message.split(\"attack_type:\")[1].indexOf(\" \"));\n" +
            "            }\n" +
            "        }\n" +
            "        resultBody.event_log = log_type;\n" +
            "\n" +
            "//{\"Priority\":\"255\",\"Severity\":\"7\",\"Facility\":\"31\",\"syslog\":\"<255>user:weboper;loginip:2.74.24.22;time:1555463929;type:2;\\n修改引擎配置\",\"message\":\"<255>user:weboper;loginip:2.74.24.22;time:1555463929;type:2;\\n修改引擎配置\",\"source_ip\":\"\",\"timestamp\":\"2019-04-17T09:26:31.264+08:00\"}\n" +
            "\n" +
            "        resultBody.event_host = body.host;\n" +
            "        resultBody.system_type = \"audit\";\n" +
            "        headers.system_type = \"audit\";\n" +
            "        resultBody.module_type = tag;\n" +
            "        headers.module_type = tag;\n" +
            "        resultBody.log_type = \"lm\";\n" +
            "        headers.log_type = \"lm\";\n" +
            "        resultBody.manufacturers = \"绿盟-WAF\";\n" +
            "        body.message = resultBody;\n" +
            "        return body;\n" +
            "    }\n" +
            "\n" +
            "    // 绿盟 nf 防火墙 解析 和安全审计\n" +
            "    if (null != message && message.indexOf(\"user:\") !== -1 && message.indexOf(\"loginip:\") !== -1\n" +
            "        && message.indexOf(\"time:\") !== -1 && message.indexOf(\"type:\") !== -1) {\n" +
            "\n" +
            "        if (body.Priority) { // 事件等级\n" +
            "            resultBody.event_level = body.Priority;\n" +
            "        }\n" +
            "\n" +
            "        resultBody.user_name = message.split(\"user:\")[1].slice(0, message.split(\"user:\")[1].indexOf(\";\"));\n" +
            "        resultBody.login_ip = message.split(\"loginip:\")[1].slice(0, message.split(\"loginip:\")[1].indexOf(\";\"));\n" +
            "        resultBody.type = message.split(\"type:\")[1].slice(0, message.split(\"type:\")[1].indexOf(\";\"));\n" +
            "        resultBody.describle = message.slice(message.lastIndexOf(\";\") + 1, message.length).replace(\"\\n\", \"\");\n" +
            "\n" +
            "        resultBody.system_type = \"audit\";\n" +
            "        headers.system_type = \"audit\";\n" +
            "        resultBody.module_type = \"nf_sas\";\n" +
            "        headers.module_type = \"nf_sas\";\n" +
            "        resultBody.log_type = \"lm\";\n" +
            "        headers.log_type = \"lm\";\n" +
            "        resultBody.manufacturers = \"绿盟-防火墙/安全审计\";\n" +
            "        body.message = resultBody;\n" +
            "        return body;\n" +
            "    }\n" +
            "\n" +
            "    // 山石 解析  边界防火墙\\互联网发布边界防火墙\\云数据中心边界防火墙\n" +
            "    if (null != message && message.indexOf(\"hillstone\") !== -1) {\n" +
            "        var priority = body.Priority;\n" +
            "        if (priority) { // 事件等级\n" +
            "            resultBody.event_level = priority;\n" +
            "        }\n" +
            "        var timestamp = body.timestamp;\n" +
            "        if (timestamp) { // 事件时间\n" +
            "            resultBody.event_time = timestamp;\n" +
            "        } else {\n" +
            "            resultBody.event_time = new Date();\n" +
            "        }\n" +
            "        resultBody.event_log_infoID = body.message.split(\" \")[0];//信息ID\n" +
            "\n" +
            "        if (message.indexOf(\"@\") !== -1) {\n" +
            "            resultBody.event_WARNING = message.split(\"@\")[0].slice(9, -1);//信息级别\n" +
            "            resultBody.event_LOGIN = message.split(\"@\")[1].slice(0, message.split(\"@\")[1].indexOf(\":\"));//信息模块\n" +
            "            resultBody.event_content = message.substring(message.indexOf(\":\") + 1);//信息内容\n" +
            "        }\n" +
            "        resultBody.event_source_ip = body.source_ip;\n" +
            "\n" +
            "        resultBody.event_host = body.host;\n" +
            "        resultBody.system_type = \"audit\";\n" +
            "        headers.system_type = \"audit\";\n" +
            "        resultBody.module_type = resultBody.event_WARNING.toLowerCase() + \"-\" + resultBody.event_LOGIN.toLowerCase();\n" +
            "        headers.module_type = resultBody.event_WARNING.toLowerCase() + \"-\" + resultBody.event_LOGIN.toLowerCase();\n" +
            "        resultBody.log_type = \"sh\";\n" +
            "        headers.log_type = \"sh\";\n" +
            "        resultBody.manufacturers = \"山石\";\n" +
            "        body.message = resultBody;\n" +
            "        return body;\n" +
            "\n" +
            "    }\n" +
            "\n" +
            "    // 网御星云   功能区防火墙\n" +
            "    if (message.indexOf(\"devid\") !== -1 && message.indexOf(\"date\") !== -1\n" +
            "        && message.indexOf(\"dname\") !== -1 && message.indexOf(\"logtype\") !== -1\n" +
            "        && message.indexOf(\"pri\") !== -1 && message.indexOf(\"ver\") !== -1) {\n" +
            "        var modutType = {\n" +
            "            \"1\": \"包过滤日志\",\n" +
            "            \"2\": \"代理日志\",\n" +
            "            \"3\": \"联动日志\",\n" +
            "            \"4\": \"VPN日志\",\n" +
            "            \"5\": \"用户认证日志\",\n" +
            "            \"6\": \"内容过滤日志\",\n" +
            "            \"7\": \"病毒防护日志\",\n" +
            "            \"8\": \"设备状态日志\",\n" +
            "            \"9\": \"设备管理日志\",\n" +
            "            \"10\": \"HA日志\",\n" +
            "            \"11\": \"可扩展\",\n" +
            "            \"12\": \"反垃圾邮件代理日志\",\n" +
            "            \"13\": \"URL过滤日志\",\n" +
            "            \"14\": \"病毒隔离日志\",\n" +
            "            \"15\": \"主机隔离日志\",\n" +
            "            \"16\": \"入侵防御日志\",\n" +
            "            \"17\": \"绿色上网日志\",\n" +
            "            \"18\": \"协议控制日志\",\n" +
            "            \"19\": \"主动防御日志\",\n" +
            "            \"20\": \"UTM日志\",\n" +
            "            \"21\": \"服务器负载均衡日志\",\n" +
            "            \"22\": \"漏洞扫描日志\",\n" +
            "            \"23\": \"UIDS模式下的病毒检测日志\",\n" +
            "            \"24\": \"UIDS模式下的入侵检测日志\",\n" +
            "            \"25\": \"端口联动日志\",\n" +
            "            \"26\": \"SSLVPN日志\",\n" +
            "            \"27\": \"域名控制日志\",\n" +
            "            \"28\": \"流量控制日志\",\n" +
            "            \"29\": \"WAF日志\",\n" +
            "            \"30\": \"邮件延迟审计\",\n" +
            "            \"31\": \"抗攻击类型日志\",\n" +
            "            \"32\": \"私有云防护\",\n" +
            "            \"33\": \"pki日志\"\n" +
            "        }\n" +
            "        var event_pri = {\n" +
            "            \"0\": \"（emergency）紧急，导致系统不可用的事件消息\",\n" +
            "            \"1\": \"（alert）警报，应立即采取应对行动的事件消息\",\n" +
            "            \"2\": \"（critical）临界，达到临界条件的事件消息\",\n" +
            "            \"3\": \"（error）出错，一般出错事件消息\",\n" +
            "            \"4\": \"（warning）预警，预警性提示事件消息\",\n" +
            "            \"5\": \"（notice）提示，重要的正常事件消息\",\n" +
            "            \"6\": \"（information）通知，一般性的正常事件消息\",\n" +
            "            \"7\": \"（debug）调试，调试消息\"\n" +
            "        }\n" +
            "        var key;\n" +
            "        var value;\n" +
            "        var array = message.substring(message.indexOf(\" \") + 1).split(\"=\");\n" +
            "        for (i = 0; i < array.length; i++) {\n" +
            "            if (i == 0) {\n" +
            "                key = array[i];\n" +
            "                value = array[i + 1].substring(0, array[i + 1].lastIndexOf(\" \"));\n" +
            "\n" +
            "            } else if (i == array.length - 1) {\n" +
            "                key = array[i - 1].substring(array[i - 1].lastIndexOf(\" \") + 1);\n" +
            "                value = array[i];\n" +
            "            } else if (i == array.length - 2) {\n" +
            "                continue;\n" +
            "            } else {\n" +
            "                key = array[i].substring(array[i].lastIndexOf(\" \") + 1);\n" +
            "                value = array[i + 1].substring(0, array[i + 1].lastIndexOf(\" \"));\n" +
            "            }\n" +
            "            resultBody[\"event_\" + key] = value;\n" +
            "        }\n" +
            "        resultBody.event_logtype = modutType[resultBody.event_logtype];\n" +
            "        resultBody.event_pri = event_pri[resultBody.event_pri];\n" +
            "\n" +
            "\n" +
            "        resultBody.event_host = body.host;\n" +
            "        resultBody.system_type = \"audit\";\n" +
            "        headers.system_type = \"audit\";\n" +
            "        resultBody.module_type = \"firewall\";\n" +
            "        headers.module_type = \"firewall\";\n" +
            "        resultBody.log_type = \"wyxx\";\n" +
            "        headers.log_type = \"wyxx\";\n" +
            "        resultBody.manufacturers = \"网御星云\";\n" +
            "        body.message = resultBody;\n" +
            "        return body;\n" +
            "    }\n" +
            "\n" +
            "    // 华为 交换机\n" +
            "    //body:{\"Priority\":\"189\",\"host\":\"7:13\",\"Severity\":\"5\",\"Facility\":\"23\",\n" +
            "    // \"syslog\":\"<189>Apr 19 2019 13:57:13 DC_FACCSW131 %%01SHELL/5/CMDRECORD(s)[10]:Recorded command information. (Task=We0, Ip=172.28.15.183, VpnName=, User=admin, AuthenticationMethod=\\\"Local-user\\\", Command=\\\"info-center timestamp log date\\\")\",\n" +
            "    // \"message\":\"DC_FACCSW131 %%01SHELL/5/CMDRECORD(s)[10]:Recorded command information.\n" +
            "    //  (Task=We0, Ip=172.28.15.183, VpnName=, User=admin, AuthenticationMethod=\\\"Local-user\\\",\n" +
            "    //      Command=\\\"info-center timestamp log date\\\")\",\n" +
            "    // \"source_ip\":\"\",\"timestamp\":\"2019-04-19T14:15:19.842+08:00\"}\n" +
            "\n" +
            "}";
    public static void main(String[] args) {
        String body = "{\"Priority\":\"255\",\"host\":\"[127, 0, 0, 1]\",\"Severity\":\"7\",\"Facility\":\"31\",\"syslog\":\"<255>user:weboper;loginip:2.74.24.21;time:2019-06-13 14:37:08;type:1;\\n登录成功\",\"message\":\"14:37:08;type:1;\\n登录成功\",\"source_ip\":\"100.73.26.165\",\"timestamp\":\"2019-06-13T14:25:27.075+08:00\"}";

        IParser parser = JsDynamicCompiler.get().compileAndBuild(IParser.class, scriptContent);
        SimpleEvent event=new SimpleEvent();
        event.setHeaders(new HashMap<>());
        event.setBody(body.getBytes());

        String s = new String(event.getBody(), StandardCharsets.UTF_8);
        System.out.println(s);
        Object data = parser.parse(event.getHeaders(),s,"string");
        System.out.println(String.valueOf(data));
        logger.info("解析日志:\t" + new String(JsonEventConverter.get().convert(data), StandardCharsets.UTF_8));
    }
}
