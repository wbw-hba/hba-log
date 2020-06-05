package cn.hba.audit.flume.source.interceptor;

import cn.hutool.core.util.NumberUtil;
import org.junit.Test;

/**
 * 字符串测试
 * @author wbw
 * @date 2020/1/7 9:22
 */
public class StrTest {
    @Test
    public void test01() {
        String str = "\"OK\"";
        if (str.startsWith("\"")) {
            System.out.println(str.replaceAll("\"", ""));
        }
    }

    @Test
    public void testNum() {
        String aa = "xxax";
        System.out.println(NumberUtil.isNumber(aa));
    }
}
