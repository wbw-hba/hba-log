package cn.hba.audit.flume.logs;

import cn.hutool.core.io.FileUtil;
import cn.hutool.log.Log;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * 文件操作
 *
 * @author wbw
 * @date 2019/12/4 19:59
 */
public class FileLogUtil {
    private static Log log = Log.get();

    /**
     * 对文件夹内文件名修改后缀
     *
     * @param folder 文件夹
     * @param suffix 后缀
     */
    private static void updateFileNameSuffix(String folder, String suffix) {
        FileUtil.loopFiles(folder, file -> file.getName().endsWith(suffix))
                .forEach(e -> log.info(e.getName() + "\t" + e.renameTo(new File(e.getAbsolutePath() + suffix))));
    }

    private static Map<String, String> map = new HashMap<>();

    static {
        String h3cSecurityName = "H3C-安全产品-";
        String h3cSecurityIp = "192.168.137.5\t192.168.130.3\t192.168.9.16\t192.168.9.15\t192.168.9.14\t192.168.9.11\t192.168.9.10\t" +
                "192.168.9.6\t192.168.9.5\t192.168.9.4\t192.168.9.2\t192.168.9.1\t192.168.9.8\t192.168.9.9\t" +
                "192.168.9.17\t192.168.9.18\t192.168.9.19\t192.168.9.20\t192.168.137.3";
        Arrays.stream(h3cSecurityIp.split("\t")).forEach(v -> map.put(v, h3cSecurityName));

        String hscAuditName = "H3C-运维审计-";
        String hscAuditIp = "192.168.6.162\t192.168.134.154";
        Arrays.stream(hscAuditIp.split("\t")).forEach(v -> map.put(v, hscAuditName));

        String aptName = "APT-安全事件-";
        String aptIp = "192.168.81.203";
        Arrays.stream(aptIp.split("\t")).forEach(v -> map.put(v, aptName));

        String wsWaf = "网神-waf-";
        String wafIp = "192.168.124.251";
        Arrays.stream(wafIp.split("\t")).forEach(v -> map.put(v, wsWaf));

        String rsRaName = "瑞数防爬-";
        String rsRaIp = "192.168.109.40\t192.168.107.100\t192.168.103.60\t192.168.92.104\t192.168.92.103\t192.168.50.1\t192.168.101.18\t" +
                "192.168.113.203";
        Arrays.stream(rsRaIp.split("\t")).forEach(v -> map.put(v, rsRaName));

        String sxfName = "深信服-";
        String sxfIp = "192.168.3.10\t192.168.83.7";
        Arrays.stream(sxfIp.split("\t")).forEach(v -> map.put(v, sxfName));

        String kpName = "科博-安全-";
        String kbIp = "192.168.6.115\t192.168.6.114\t192.168.134.117\t192.168.134.116\t192.168.134.115\t192.168.134.114";
        Arrays.stream(kbIp.split("\t")).forEach(v -> map.put(v, kpName));

        String name360 = "360-跨网防火墙-";
        String ip360 = "192.168.131.9\t192.168.131.12";
        Arrays.stream(ip360.split("\t")).forEach(v -> map.put(v, name360));
    }

    /**
     * 根据已知ip修改文件名
     *
     * @param folder 文件夹
     */
    private static void updateFileByName(String folder) {
        FileUtil.loopFiles(folder, file -> map.containsKey(file.getName().replace(".log", ""))).forEach(e -> {
            String ip = e.getName().replace(".log", "");
            log.info(e.getName() + "\t" + e.renameTo(new File(e.getAbsolutePath().replace(ip, map.get(ip) + ip))));
        });
    }

    public static void main(String[] args) {
//        updateFileNameSuffix("F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志文件", ".log");
        updateFileByName("F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志筛选\\2020-1-1");
    }
}
