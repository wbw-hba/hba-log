package cn.hba.audit.flume.logs;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.log.Log;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 读取flume原始日志,lambda 改造
 *
 * @author wbw
 * @date 2019/12/2 9:00
 */
public class FlumeLogUtil {
    private static Log log = Log.get();

    /**
     * 根据文件夹路径写入数据
     *
     * @param folder 文件夹
     * @param map    数据
     */
    private static void writeTextLog(String folder, Map<String, List<String>> map) {
        final String finalFolder = FileUtil.isDirectory(folder) ? FileUtil.getAbsolutePath(folder) : FileUtil.mkdir(folder).getAbsolutePath();
        map.forEach((k, v) -> {
            String path = finalFolder + File.separator + k + ".log";
            FileUtil.writeLines(v, path, CharsetUtil.UTF_8, true);
            log.info("文件写入成功:\t{}", path);
        });

    }

    /**
     * 读取每个文本数据
     *
     * @param path 路径
     * @return ip，文本
     */
    private static Map<String, List<String>> readLog(String path) {
        if (!FileUtil.isFile(path)) {
            log.info("路径错误:\t{}", path);
            return Collections.emptyMap();
        }
        return disReadLines(FileUtil.readLines(path, CharsetUtil.UTF_8));
    }

    private static final String IP = "-  ip 地址:";
    private static final String SYSLOG = "-  syslog 信息:";

    /**
     * 处理每一行数据
     *
     * @param list 数据
     * @return map
     */
    private static Map<String, List<String>> disReadLines(List<String> list) {
        Map<String, List<String>> map = CollUtil.createMap(LinkedHashMap.class);
        List<String> collect = list.stream().filter(v -> v.contains("-  ip 地址:") || v.contains("-  syslog 信息:")).collect(Collectors.toList());
        collect.forEach(e -> {
            if (e.contains("-  ip 地址:")) {
                String ip = StrUtil.trim(e.split(IP)[1]);
                if (!map.containsKey(ip)) {
                    map.put(ip, new LinkedList<>());
                }
                int index = collect.indexOf(e);
                if (index + 1 < collect.size()) {
                    map.get(ip).add(StrUtil.trim(collect.get(index + 1).split(SYSLOG)[1]));
                }
            }
        });
        return map;
    }

    /**
     * 根据文件夹内文件日志生成新的数据到指定文件夹
     *
     * @param redFolder   读取文件夹
     * @param suffix      后缀
     * @param writeFolder 写入文件夹
     */
    private static void writeLogByFolder(String redFolder, String suffix, String writeFolder) {
        if (StrUtil.isBlank(suffix)) {
            log.info("后缀错误:\t{}", suffix);
            return;
        }
        redFolder = !FileUtil.isDirectory(redFolder) ? FileUtil.mkdir(redFolder).getAbsolutePath() : FileUtil.getAbsolutePath(redFolder);
        final String finalWriteFolder = !FileUtil.isDirectory(writeFolder)
                ? FileUtil.mkdir(writeFolder).getAbsolutePath() : FileUtil.getAbsolutePath(writeFolder);
        FileUtil.loopFiles(redFolder, path -> (path.getName().contains(suffix)) || path.isDirectory()).forEach(e -> {
            if (e.isFile()) {
                writeTextLog(finalWriteFolder, readLog(e.getAbsolutePath()));
            } else {
                writeLogByFolder(e.getAbsolutePath(), suffix, finalWriteFolder);
            }
        });
    }

    public static void main(String[] args) {
        writeLogByFolder("F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志文件"
                , ".log", "F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志筛选\\2020-1-1");
    }
}
