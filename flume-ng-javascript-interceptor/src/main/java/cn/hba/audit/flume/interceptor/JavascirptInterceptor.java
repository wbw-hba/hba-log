//package cn.hba.audit.flume.interceptor;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.google.gson.JsonObject;
//import org.apache.commons.collections.MapUtils;
//import org.apache.flume.Context;
//import org.apache.flume.Event;
//import org.apache.flume.FlumeException;
//import org.apache.flume.interceptor.Interceptor;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//import javax.script.*;
//import java.io.File;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.util.List;
//import java.util.Map;
//
//public class JavascirptInterceptor implements Interceptor {
//
//    private static final Logger logger = LoggerFactory.getLogger(org.apache.flume.interceptor.StaticInterceptor.class);
//    private IParser parser;
//
//    public JavascirptInterceptor(String scriptContent) {
//        try {
//            parser = JsDynamicCompiler.get().compileAndBuild(IParser.class, scriptContent);
//            logger.info("脚本编译成功 ");
//        } catch (Exception e) {
//            logger.error("脚本编译失败", e);
//            throw new FlumeException(e);
//        }
//    }
//
//    @Override
//    public void initialize() {
//        // no-op
//    }
//
//
//    @Override
//    public Event intercept(Event event) {
//        String stringBody = new String(event.getBody(), StandardCharsets.UTF_8);
//        logger.info("接收日志 - body:\t" + stringBody);
//        logger.info("接收日志 - headers:\t" + event.getHeaders());
//        try {
//            Object body = parser.parse(event.getHeaders(), stringBody, "string");
//            if (body instanceof String) {
//                event.setBody(((String)body).getBytes(StandardCharsets.UTF_8));
//            } else {
//                event.setBody(JsonEventConverter.get().convert(body));
//            }
//            logger.info("解析日志完成:\t" + new String(event.getBody(), StandardCharsets.UTF_8));
//        } catch (Exception e) {
//            logger.error("解析syslog错误", e);
//        }
//        return event;
//    }
//
//    /**
//     * Delegates to {@link #intercept(Event)} in a loop.
//     *
//     * @param events
//     * @return
//     */
//    @Override
//    public List<Event> intercept(List<Event> events) {
//        for (Event event : events) {
//            intercept(event);
//        }
//        return events;
//    }
//
//    @Override
//    public void close() {
//        // no-op
//    }
//
//    /**
//     * Builder which builds new instance of the StaticInterceptor.
//     */
//    public static class Builder implements Interceptor.Builder {
//
//        private String scriptContent;
//        private String scriptPath;
//
//        @Override
//        public void configure(Context context) {
//            scriptPath = context.getString("scriptPath");
//            scriptContent = context.getString("scriptContent", "");
//        }
//
//        @Override
//        public Interceptor build() {
//            File scriptFile = new File(scriptPath);
//            try {
//                logger.debug("js脚本配置:{}", scriptFile.getAbsoluteFile());
//                scriptContent = new String(Files.readAllBytes(scriptFile.toPath()), StandardCharsets.UTF_8);
//            } catch (IOException e) {
//                logger.error("文件未找到", e);
//                throw new FlumeException(e);
//            }
//            return new JavascirptInterceptor(scriptContent);
//        }
//
//    }
//
//}
