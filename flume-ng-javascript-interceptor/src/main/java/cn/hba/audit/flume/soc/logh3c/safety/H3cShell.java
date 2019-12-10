package cn.hba.audit.flume.soc.logh3c.safety;

import cn.hutool.json.JSONObject;

/**
 * Shell 类型处理
 *
 * @author wbw
 * @date 2019/12/5 9:08
 */
class H3cShell {

    static void disLogShell(String bo, JSONObject obj) {
        obj.put("message_content", bo);
        switch (obj.getStr("abstract").toUpperCase()) {
            case "SHELL_CMD":
                obj.put("message_content_explain", "用户执行cmd命令.");
                break;
            case "SHELL_CMD_MATCHFAIL":
                obj.put("message_content_explain", "由于命令输入错误，或者当前模式错误等，造成命令匹配错误.");
                break;
            case "SHELL_LOGIN":
                obj.put("message_content_explain", "用户成功登录.");
                break;
            case "SHELL_LOGOUT":
                obj.put("message_content_explain", "用户退出登录.");
                break;
            case "SHELL_COMMIT":
                obj.put("message_content_explain", "配置提交成功.");
                break;
            case "SHELL_CMDDENY":
                obj.put("message_content_explain", "命令执行失败。用户权限不够.");
                break;
            default:
                obj.put("message_content_explain", "命令.");
        }
    }
}
