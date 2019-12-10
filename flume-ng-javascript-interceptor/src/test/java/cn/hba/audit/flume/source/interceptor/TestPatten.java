package cn.hba.audit.flume.source.interceptor;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.text.UnicodeUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.json.JSONUtil;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class TestPatten {

    public static void main(String[] args) {
        String aaa = "[\"sss\",\"aaa\"]";
        if (JSONUtil.isJsonArray(aaa)){
            System.out.println(JSONUtil.parseArray(aaa).join(","));
        }
    }


    @Test
    public void test01() throws UnsupportedEncodingException {
        String http = "\\u0019��R�J�\\\"�h\\u000f�[\\u0005\\u000f���1on(.IńJ+�s��,��Y<+���v�H�[��x����l��/\\u001c�>k�}����`��Z�a]�\\u0002�\\u000f ��ys��Cj��b��B\\\"F\\u0012�Ê�e�C�N��|Y��7\\u0005}���-�ZF�][U�{��j����\\u0007\\u0004zs|�\\u0004\\u0007^Gޞ�!˥���i<\\u0006���$�L�wm��";
         String n = new String(http.getBytes("GB2312"),"GB2312");
        System.out.println(http);
    }
}
