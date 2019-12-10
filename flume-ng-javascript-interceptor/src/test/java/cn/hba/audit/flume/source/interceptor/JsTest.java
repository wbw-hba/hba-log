package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.interceptor.IParser;
import cn.hba.audit.flume.interceptor.JsDynamicCompiler;
import cn.hba.audit.flume.interceptor.JsonEventConverter;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.apache.flume.event.SimpleEvent;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;

public class JsTest {
    @Test
    public void testCompiler() {
        String js = "function parse(headers,body,type){" +
                "var o=JSON.stringify({a:1,b:2});" +
                "headers.test=o;" +
                "return {body:{\"Priority\":\"255\",\"host\":\"127.0.0.1\",\"Severity\":\"7\",\"Facility\":\"31\",\"syslog\":\"<255>user:weboper;loginip:2.74.24.21;time:2019-06-13 11:33:43;type:1;\\n登录成功\",\"message\":\"11:33:43;type:1;\\n登录成功\",\"source_ip\":\"100.73.26.165\",\"timestamp\":\"2019-06-13T11:22:02.671+08:00\"}\n};" +
                "}";

        IParser parser = JsDynamicCompiler.get().compileAndBuild(IParser.class, js);
        SimpleEvent event=new SimpleEvent();
        event.setHeaders(new HashMap<>());
        event.setBody("sdsf".getBytes());
//        Object data = parser.parse(String.valueOf(event.getHeaders()),new String(event.getBody(), StandardCharsets.UTF_8),"string");
//        System.out.print(Arrays.toString(JsonEventConverter.get().convert(data)));

    }

    @Test
    public void json(){
        JSONObject obj = JSONUtil.parseObj("{'log_dp':'127.0.0.1,10.0.1.89'}");
        System.out.println( Arrays.asList(obj.getStr("log_dp").split(",")));
    }
}
