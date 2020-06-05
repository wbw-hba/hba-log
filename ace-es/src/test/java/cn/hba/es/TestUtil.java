package cn.hba.es;

import cn.hutool.json.JSONUtil;
import org.junit.Test;

/**
 * @author wbw
 * @date 2019/11/4 13:58
 */
public class TestUtil {
    @Test
    public void test01() {
//        ElasticSearchUtil.getClusterInfo();
    }


    @Test
    public void test02() {
        String addrStr = "{'127.0.0.1':9310,'10.0.1.89':9310}";
        System.out.println(JSONUtil.parseObj(addrStr).toJSONString(2));
    }
}
