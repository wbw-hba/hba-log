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
        String syslog = "<12>Dec 26 02:48:14 slave4 apt: 2019-12-26 02:47:53 1577299673422 ATD 192.168.123.5 NDE 28a5af08-3d54-4034-a5af-083d54703419 p5p1 2027265 bad-unknown bad-unknown null 192.168.103.21 58868 null 59.202.42.251 80 http tcp http security-defect R0VUIC9saWNlbnNlbmFtZS9zaWduL2VsY2xpY2VuY2VwZGYveWpqL2h6cHNjeGt6L01MMDAwNDExNjQ5YmY2NzY5ODZlZWFiZjU2YTdhOGRhNzY2OGVlOTcucGRmIEhUVFAvMS4xDQphY2NlcHQ6ICovKg0KdXNlci1hZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNi4wOyBXaW5kb3dzIE5UIDUuMTtTVjEpDQpDYWNoZS1Db250cm9sOiBuby1jYWNoZQ0KUHJhZ21hOiBuby1jYWNoZQ0KSG9zdDogNTkuMjAyLjQyLjI1MQ0KQ29ubmVjdGlvbjoga2VlcC1hbGl2ZQ0KDQo= null 1 1 null Dotted Quad Host PDF Request method:GET;status_code:200;host:59.202.42.251;uri:/licensename/sign/elclicencepdf/yjj/hzpscxkz/ML000411649bf676986eeabf56a7a8da7668ee97.pdf; Dotted Quad Host PDF Request China beijing 39.9047,116.4072 CN China Beijing 39.9289,116.3883 CN";
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
