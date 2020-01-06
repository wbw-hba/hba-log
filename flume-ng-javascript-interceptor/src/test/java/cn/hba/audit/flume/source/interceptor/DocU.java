package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.soc.SyslogParseChannels;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
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
        String syslog = "<133>Dec 28 15:08:48 wangzhaWC charset=UTF-8 type=dbsync instanceName=数据库同步集群模式 taskName=ceshi-menhu-haochaping-wai-nei resourceInfo=[ip=192.168.221.5,port=3306,sid=tyhcp_pjfxgl,username=wangzha] logLevel=(5) 通知 logType=数据采集 objectName=增量同步中转包,标识[1577446321054-15088],大小[1067][1.04 KB] desc=同步中转完成.记录数[1],目的库[[ip=192.168.92.196,port=3306,sid=tyhcp_pjfxgl,username=wztb]] result=成功 date=2019-12-28 15:08:48.972";
        String body = "{\n" +
                "    \"Priority\":\"6\",\n" +
                "    \"host\":\"[127, 0, 0, 1]\",\n" +
                "    \"Severity\":\"6\",\n" +
                "    \"Facility\":\"0\",\n" +
                "    \"syslog\":\"" + syslog + "\"\n" +
                "}";
        Map<String, String> map = new HashMap<>();
        map.put("facility_ip", "127.0.0.1");
        Event intercept = new SyslogParseChannels().intercept(false, convert(JSONUtil.parseObj(body), map));
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
