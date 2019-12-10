package cn.hba.audit.flume.util;

/**
 * @author wbw
 * @date 2019/9/10 15:16
 */
public class StringUtil {

    /**
     * 是否全部包含
     *
     * @param message  字符串
     * @param c 包含的内容
     * @return 真假值
     */
    public static boolean containsAll(String message, String... c) {
        for (String contain : c) {
            if (!message.contains(contain)) {
                return false;
            }
        }
        return true;
    }
}
