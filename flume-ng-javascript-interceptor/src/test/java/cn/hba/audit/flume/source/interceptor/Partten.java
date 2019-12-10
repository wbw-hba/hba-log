package cn.hba.audit.flume.source.interceptor;

import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.ReUtil;
import org.junit.Test;

import java.util.Arrays;

/**
 * @author wbw
 * @date 2019/9/6 18:48
 */
public class Partten {

    public static void main(String[] args) {
        String data ="<142> 1 1.1.1.1 2013 Nov 26 11:43:16 FW 123 NAT444:SessionW 1320370756|1320370759|10.1.249.2|124.207.3.12|10256|219.207.3.12|80|6";
        boolean contains = ReUtil.isMatch("[\\|]*", data);
        System.out.println("(\\|.){7}");
        System.out.println(contains);
        System.out.println(Arrays.toString(data.split("\\|")));
        System.out.println(data.split("\\|").length);
    }

    @Test
    public void idnull(){
        Assert.isTrue(""!=null);
    }
}
