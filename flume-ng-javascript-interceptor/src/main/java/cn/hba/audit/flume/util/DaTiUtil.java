package cn.hba.audit.flume.util;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;

/**
 * syslog 时间处理
 *
 * @author wbw
 * @date 2019-12-05 20:45
 */
public class DaTiUtil {

    public static void main(String[] args) {
        // Thu Dec 05 21:55:51 CST 2019
        System.out.println(disEventTime("<12>Jan  9 15:43:01 slave4 apt: 2020-01-09 15:43:26\t1578555806767\tATD\t192.168.123.5\tNDE\taafa7329-58d5-40b2-ba73-2958d580b24b\tp5p1\t10180004\tthreat-intelligence-alarm\toutbound2malicious-server\tRemote control tool Pupy\t192.168.6.154\t50841\tnull\t192.168.6.161\t443\thttps\ttcp\tssl\tremote-control\tnull\tnull\t5\t5\tRemote control tool Pupy\te35df3e00ca4ef31d42b34bebaa2f86e\tsource:5;\n"));
    }

    public static final String FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

    /**
     * 格式：
     * <132>Dec 05 09:14:12 node1 H3C-A2020-G:
     * <20> Dec 05 16:00:01 2019 System_ID=H3C
     * <182>Oct 22 10:20:07 NS : 操作日志,
     * <190>Jul 9 10:25:28 1304415172004234(root)
     * <11>Sep 11 11:23:42 localhost
     * <14>2019-09-19 15:42:18 DPTEC
     *
     * @param syslog 日志
     * @return yyyy-MM-dd'T'HH:mm:ss.SSSXXX
     */
    public static String disEventTime(String syslog) {
        String date = DateUtil.date().toString(FORMAT);
        try {
            String log = StrUtil.trim(syslog);
            if (!syslog.startsWith("<") || syslog.indexOf(">") > 5) {
                return date;
            }
            log = StrUtil.trim(log.substring(log.indexOf(">") + 1));
            String[] da = log.split(":");
            String[] ti = da[2].split(" ");
            String time = da[0] + ":" + da[1] + ":" + ti[0];
            if (NumberUtil.isNumber(ti[1]) && ti[1].length() == 4) {
                time += " " + ti[1];
            }
            try {
                // 常见格式处理
                return DateUtil.parse(time).toString(FORMAT);
            } catch (Exception ignored) {
            }
            // Dec 05 16:00:01 2019
            String[] dt = time.replaceAll("\t", " ")
                    .replaceAll(" +", " ").split(" ");
            String dateTime = (dt.length == 4 ? dt[3] : String.valueOf(DateUtil.year(DateUtil.date())))
                    + "-" + disMonth(dt[0]) + "-" + (dt[1].length() == 1 ? "0" + dt[1] : dt[1]) + " " + dt[2];
            date = DateUtil.parse(dateTime).toString(FORMAT);
        } catch (Exception ignored) {
        }
        return date;
    }

    /**
     * 处理十二个月份
     *
     * @param month 月份
     * @return 月
     */
    private static String disMonth(String month) {
        if ("January".contains(month)) {
            return "01";
        } else if ("February".contains(month)) {
            return "02";
        } else if ("March".contains(month)) {
            return "03";
        } else if ("April".contains(month)) {
            return "04";
        } else if ("May".contains(month)) {
            return "05";
        } else if ("June".contains(month)) {
            return "06";
        } else if ("July".contains(month)) {
            return "07";
        } else if ("August".contains(month)) {
            return "08";
        } else if ("September".contains(month)) {
            return "09";
        } else if ("October".contains(month)) {
            return "10";
        } else if ("November".contains(month)) {
            return "11";
        } else {
            return "12";
        }
    }

}
