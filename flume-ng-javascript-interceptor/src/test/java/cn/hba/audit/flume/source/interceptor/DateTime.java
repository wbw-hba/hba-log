package cn.hba.audit.flume.source.interceptor;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import org.junit.Test;

/**
 * @author wbw
 * @date 2019/9/6 18:14
 */
public class DateTime {
    @Test
    public void par(){
        String date  = "2019-07-02T16:52:08.679+08:00";
        System.out.println(DateUtil.parse(date, "yyyy-MM-dd'T'HH:mm:ss.SSS"));

        System.out.println(DateUtil.date(0));
        System.out.println(DateUtil.parse("19700101081609"));

        String eventTime = "\"2019-09-19 14:21:52\"";
        if (eventTime.startsWith("\"")){
            eventTime = eventTime.substring(1);
        }
        if (eventTime.endsWith("\"")){
            eventTime = eventTime.substring(0,eventTime.length()-1);
        }
        System.out.println(DateUtil.parse(eventTime).toMsStr());
    }
}
