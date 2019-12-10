package cn.hba.test;

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
    public void indexTest(){
        List<String> list = Stream.of("a","b","c").collect(Collectors.toList());
        System.out.println(list.indexOf("a"));
    }
}
