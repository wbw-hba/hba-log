package cn.hba.audit.flume.soc.log.logkb;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author ikas
 */
public class SyslogParseKb implements SyslogParse {
    @Override
    public Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");

        return KbParse.parse(body);
    }


    public static void main(String[] args) {
        SyslogParse parse = new SyslogParseKb();
        String sys = "<133>Dec 04 11:07:29 wangzhaWD charset=UTF-8 type=fileTransfer instanceName=文件接收实例 taskName=dbSyncFileTransfer logLevel=(5) 通知 logType=实例运行 objectName=/copFile/dbSync_file/GB-MH-JCMS1205-WAI_front_storage_1/19238229-19238230.sql.zz desc=开始接收文件[18519 Byte ][18.0849609375 KB ] result=成功 date=2019-12-04 11:07:29.970";
        //sys = "<133>Dec 04 18:21:16 wangzhaNA charset=UTF-8 type=systemService serviceName=服务调用摆渡中转服务 desc=生成摆渡响应数据文件[f4511c9d-a790-4a7f-b660-692a999ea276],对应请求[f4511c9d-a790-4a7f-b660-692a999ea276] result=成功 date=2019-12-04 18:21:16.566";
        //sys = "<131>Dec 04 11:00:12 wangzhaWA charset=UTF-8 type=filesync instanceName=文件入库实例 taskName=7-9-GB-MH-92-8TP-0530_front_storage logLevel=(3) 错误 logType=连接 objectName=host[192.168.221.40]port[21]user[ftp] desc=文件服务器连接失败[FTP response 421 received.  Server closed connection.] result=失败 date=2019-12-04 11:00:12.871";
        //sys = "<133>Dec 04 18:19:20 wangzhaNB charset=UTF-8 type=dbsync instanceName=数据库数据采集实例 taskName=DZYZ-seal_publish_sm2-G-H-Z-1107_back_collect_1 resourceInfo=mysql5 logLevel=(5) 通知 logType=采集数据 objectName=/DZYZ-seal_publish_sm2-G-H-Z-1107_front_storage_1/00077113-00077114.sql.zz desc=生成文件.记录变更数[2] result=成功 date=2019-12-04 18:19:20.616";
        //sys = "<133>Dec 04 11:00:09 wangzhaWA charset=UTF-8 type=webServiceProxyFileMode instanceName=WebService服务调用 taskName=GB-TYRZ-38010 logLevel=(5) 通知 clientIp=192.168.181.103 request=POST /rest/inside/res/corp/companySysCheck response=N/A desc=生成摆渡请求数据文件[3a9d47ad-90bf-41a8-af68-db0d71df85c7] result=成功 date=2019-12-04 11:00:09.864";
        sys = "<131>Dec 28 15:12:01 wangzhaWB charset=UTF-8 type=dbsync instanceName=数据库同步集群模式 taskName=DZYZ-sealmake-G-H resourceInfo=[ip=192.168.199.102,port=3306,sid=seal_make_sm2,username=netgap] logLevel=(3) 错误 logType=预处理 objectName=建立连接 desc=连接失败:Communications link failure";
        JSONObject object = JSONUtil.createObj();
        object.put("syslog", sys);
        Object res = parse.parse(object.toString());
        System.out.println(JSONUtil.parseObj(res).toJSONString(2));
    }
}
