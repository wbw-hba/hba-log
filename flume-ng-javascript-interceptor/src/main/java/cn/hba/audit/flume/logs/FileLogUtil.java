package cn.hba.audit.flume.logs;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.resource.ResourceUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.json.JSONUtil;
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
        String ipConfig = FileUtil.readString(ResourceUtil.getResource("ip.conf"), CharsetUtil.UTF_8);
        ipConfig = ipConfig.replaceAll("\t", "").replaceAll("\n", "");
        JSONUtil.parseObj(ipConfig).forEach((k, v) -> Arrays.stream(String.valueOf(v).split(",")).forEach(ip -> map.put(ip, k + "-")));
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
        updateFileByName("F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志筛选\\2020-1-9");
    }
}
