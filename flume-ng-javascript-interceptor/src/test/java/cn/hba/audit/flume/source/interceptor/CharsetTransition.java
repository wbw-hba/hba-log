package cn.hba.audit.flume.source.interceptor;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;

/**
 * @author wbw
 * @date 2019/10/23 9:02
 */
public class CharsetTransition {

    public static void main(String[] args) {

        String ch = "20191022 09:39:01 Gateway |5|0x02000488|User|Login|shenjjtest|Success|鐢ㄦ埛[shenjjtest:鏈\uE100湴璁よ瘉], 鑾峰彇NC IP[2.75.164.1].";
        System.out.println(Convert.convertCharset(ch, CharsetUtil.GBK,CharsetUtil.UTF_8));

    }
}
