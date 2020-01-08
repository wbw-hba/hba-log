package cn.hba.audit.flume.logs;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.log.Log;

import java.io.IOException;
import java.net.*;
import java.util.Scanner;

/**
 * udp 协议发送数据
 *
 * @author wbw
 * @date 2019/12/5 9:21
 */
public class UdpSendUtil {
    private Log log = Log.get(UdpSendUtil.class);
    private static final String IP = "10.0.1.89";
    private static InetAddress address = null;

    /**
     * 初始化 InetAddress
     *
     * @return InetAddress
     */
    private InetAddress initInAddress() {

        try {
            if (address == null) {
                address = InetAddress.getByName(IP);
            }
        } catch (UnknownHostException e) {
            log.error("初始化地址错误", e);
            return null;
        }
        return address;
    }

    /**
     * 发送数据
     *
     * @param data    数据
     * @param address InetAddress
     * @param port    端口
     */
    public void sendPacket(String data, InetAddress address, int port) {
        byte[] bytes = StrUtil.bytes(data);
        DatagramPacket dp = new DatagramPacket(bytes, bytes.length, address, port);
        try (DatagramSocket ds = new DatagramSocket()) {
            ds.send(dp);
        } catch (SocketException e) {
            log.error("对象创建失败", e);
        } catch (IOException e) {
            log.error("数据包发送失败", e);
        }
    }

    /**
     * 读取syslog 发送数据
     *
     * @param folder 文件夹
     * @param port   端口
     * @param suffix 文件名后缀
     */
    public void readSyslogSend(String folder, int port, String suffix, String conFileName) {
        if (!FileUtil.isDirectory(folder)) {
            log.debug("不是文件夹:\t{}", folder);
        }
        FileUtil.loopFiles(folder, path -> path.getName().endsWith(suffix) && path.getName().contains(conFileName)).forEach(e -> {
            log.info("处理文件:\t{}", e.getName());
            FileUtil.readLines(e, CharsetUtil.UTF_8).forEach(out -> this.sendPacket(out, this.initInAddress(), port));
        });
    }

    /**
     * 获取文件ip地址
     *
     * @param name   文件名
     * @param suffix 后缀
     * @return ip
     */
    private String getIpByFileName(String name, String suffix) {
        if (name.contains("-")) {
            String[] split = name.split("-");
            name = split[split.length - 1];
        }
        if (name.endsWith(suffix)) {
            name = name.substring(0, name.indexOf(suffix));
        }
        return name;
    }

    public static void main(String[] args) {
        UdpSendUtil udpSendUtil = new UdpSendUtil();
        String in;
        do {
            System.out.print("请输入日志名称:\t");
            Scanner scanner = new Scanner(System.in);
            in = scanner.next();
            udpSendUtil.readSyslogSend("F:\\Desktop\\2019-11-28-北京-安管\\北京-es-采集\\原始日志-2020-1-1\\日志筛选\\2020-1-7"
                    , 514, ".log", in);
        } while (StrUtil.isNotBlank(in));
    }
}