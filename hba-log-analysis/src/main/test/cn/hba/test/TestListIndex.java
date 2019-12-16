package cn.hba.test;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.SecureUtil;
import com.google.common.hash.HashCode;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author wbw
 * @date 2019/12/9 13:43
 */
public class TestListIndex {
    @Test
    public void indexTest() {
//        List<String> list = Stream.of("a","b","c").collect(Collectors.toList());
//        System.out.println(list.indexOf("a"));
//        System.out.println("Uows2W4BZbOrC6n3hW5A".getBytes().length);
        String s = SecureUtil.sha256(String.valueOf(System.currentTimeMillis()));
        System.out.println(s);
    }
}
