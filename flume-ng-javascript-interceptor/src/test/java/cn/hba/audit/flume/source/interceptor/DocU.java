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
        String syslog = "<12>Jan  9 15:43:01 slave4 apt: 2020-01-09 15:43:01\t1578555781119\tATD\t192.168.123.5\tNDE\td30257df-843b-4551-8257-df843b5551ad\tp5p1\t11000022\tpolicy-violation\tweak-password\tnull\t192.168.103.23\t52314\tnull\t59.255.104.184\t8181\tnull\ttcp\thttp\tsecurity-defect\tnull\tnull\t1\t5\tnull\tnull\tmethod:POST;status_code:200;host:59.255.104.184;uri:/httpproxy;\tWeak password\tChina\tbeijing\t39.9047,116.4072\tCN\tChina\tBeijing\t39.9289,116.3883\tCN\n";
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
