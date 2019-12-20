package cn.hba.audit.flume.soc;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.apache.flume.Context;
import org.apache.flume.Event;
import org.apache.flume.interceptor.Interceptor;

import java.util.List;

/**
 * tcp 拦截器
 *
 * @author wbw
 * @date 2019/12/3 10:40
 */
public class TcpSyslogParseInterceptor implements Interceptor {
    /**
     * 是否为采集日志原始格式
     */
    private boolean isGatherLog;

    private String ipConfig;

    private SyslogParseChannels channels = new SyslogParseChannels();

    public TcpSyslogParseInterceptor(String ipConfig, boolean isGatherLog) {
        this.ipConfig = ipConfig;
        this.isGatherLog = isGatherLog;
    }

    @Override
    public void initialize() {
        channels.loadFacilityIp(ipConfig);
    }

    @Override
    public Event intercept(Event event) {
        return channels.intercept(isGatherLog, event);
    }

    @Override
    public List<Event> intercept(List<Event> list) {
        for (Event event : list) {
            intercept(event);
        }
        return list;
    }

    @Override
    public void close() {

    }

    /**
     * Builder which builds new instance of the StaticInterceptor.
     */
    public static class Builder implements Interceptor.Builder {
        private Log log = LogFactory.get(UdpSyslogParseInterceptor.Builder.class);
        private String ipConfig;
        private boolean isGatherLog;

        @Override
        public void configure(Context context) {
            ipConfig = context.getString("ipConfig");
            isGatherLog = context.getBoolean("isGatherLog");
            log.info("Tcp device IP configuration:\t{}", ipConfig);
            log.info("Whether Tcp is the original format for the collection log:\t{}", isGatherLog);
        }

        @Override
        public Interceptor build() {
            return new UdpSyslogParseInterceptor(ipConfig, isGatherLog);
        }
    }
}