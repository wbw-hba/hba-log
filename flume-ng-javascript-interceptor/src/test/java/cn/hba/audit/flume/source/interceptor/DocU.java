package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.soc.SyslogParseChannels;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.apache.flume.Event;
import org.apache.flume.event.EventBuilder;
import org.junit.Test;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wbw
 * @date 2019/11/28 17:29
 */
public class DocU {

    public static void main(String[] args) {
        String syslog = "<133>Jan 06 11:22:52 wangzhaNB charset=UTF-8 type=fileTransfer instanceName=文件接收实例 taskName=dbSyncFileTransfer logLevel=(5) 通知 logType=实例运行 objectName=/copFile/dbSync_file/GB-DZYZ-H-G-04_back_storage_1/01002716-01002717.sql.zz-81012884PcQ.bin desc=文件接收完成,耗时[0 ms ],速度[Infinity GB/s ][Infinity B/s ] result=成功 date=2020-01-06 11:22:52.928";
        String body = "{\n" +
                "    \"Priority\":\"6\",\n" +
                "    \"host\":\"[127, 0, 0, 1]\",\n" +
                "    \"Severity\":\"6\",\n" +
                "    \"Facility\":\"0\""+
                "}";
        JSONObject object = JSONUtil.parseObj(body);
        object.put("syslog",syslog);

        Map<String, String> map = new HashMap<>();
        map.put("facility_ip", "127.0.0.1");
        Event intercept = new SyslogParseChannels().intercept(false, convert(object, map));
        String str = StrUtil.str(intercept.getBody(), CharsetUtil.UTF_8);
        System.out.println(str);
    }

    @Test
    public void test(){
        String array = "[ip=192.168.221.5,port=3306,sid=tyhcp_pjfxgl,username=wangzha]";
        System.out.println(JSONUtil.isJsonArray(array));
        System.out.println(JSONUtil.parseArray(array));
    }
    private static ObjectMapper mapper;

    static {
        mapper = new ObjectMapper();
        mapper.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE, false);

        DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        mapper.setDateFormat(fmt);
    }

    public static Event convert(Object object, Map header) {
        byte[] data;
        try {
            data = mapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return EventBuilder.withBody(data, header);
    }
}
