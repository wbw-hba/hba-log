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
        System.out.println(disEventTime("<188>Dec  4 11:13:36 SecOS 2019-12-04 11:13:36 WAF: 192.168.6.154:11970->59.255.22.68 dip=192.168.109.99 devicename=SecOS url=/audit-web/rest/epointqlk/audititem/home/audititemdetailhomeaction/page_load method=POST args=changeOrModify=1&taskguid=7c34ff26-eed0-4254-8c80-d4adec295e57&_dialogId_=559D2FD7-3B9D-46FC-A00D-BC107669EC55&_winid=w9687&_t=946817&isCommondto=true&MmEwMD=4Ptf3fyV0htTXaiTwhiI7QiXqbMlgrPMtmpK4ZYHLQFZ6.cCrFmAsVZuLDnaiJzeo40Wpnl.PlcQIfXu6IfXYdYjKxXlGEUUjVryIPYBsdA7FU_x3hFD7YrDOGp.JxFv0yMc9_nfZj0rgN4l8Osj2.itFEjhlAvgX73XS6NM_s0DFiCGkveqd243I0fh0.H3hcAypkTv.evGesfRy66skrWJTcXgFHquGM1Bs7n46aFxyQGg8vcBjVLtfbdbcvwr33mWs5gN1HPRKWv.kzi0oAp1U257QWLVwFCnAXYLcdnzp9wvEM1bcYMsfn6j9dSmpwI3veLFNYwzVQ6HeDiBfJlp4.gSlllu8OC3FfUOCu_XaCVW.j6x_Yoqg7fki8eHmST1 flag_field= block_time=0 http_type= attack_field=1 profile_id=6 rule_id=30041 type=Signature Rule severity=0 action=CONTINUE referer= useragent= post= equipment=2 os=8 browser=0 |\n"));
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
     * @return yyyy-MM-dd HH:mm:ss
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
