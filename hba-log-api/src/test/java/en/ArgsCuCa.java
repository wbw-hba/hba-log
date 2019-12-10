package en;

import org.junit.Test;

/**
 * @author wbw
 * @date 2019/11/5 12:18
 */
public class ArgsCuCa {

    @Test
    public void test01() {
        String msg = "http\thttp\ttcp\ttcp\n" +
                "ip\tip\tmac\tmac\n" +
                "web\tweb\t互联网进出口\tinternet_imex\n" +
                "链路状态\tlink_statu\t接口\tinterface\n" +
                "交换\texchange\tUDP\tudp\n" +
                "VPN\tvpn\tsession\tsession\n" +
                "公网\tpublic_network\t私网\tprivate_network\n" +
                "地址映射\taddress_mapping\t报文\tmessage\n" +
                "HA\tha\t内容\tcontent\n" +
                "扫描信息\tscan_info\t访问控制\taccess_control\n" +
                "监控\tmonitoring\t包过滤\tpacket_filter\n" +
                "URL\turl\t文件\tfile\n" +
                "ADS\tads\t连接\tconnection\n" +
                "IPS\tips\t通信\tcommunication\n" +
                "APT\tapt\t数据包\tdata_packet\n" +
                "虚拟\tvirtual\t端口\tport\n" +
                "路由\troute\t应用\tapply\n" +
                "私有云\tprivate_cloud\t上网行为\tinternet_behavior\n" +
                "ssl\tssl\t其他\tother";
//          HOST("host", "主机"), OTHER("other", "其他");
        for (String ms : msg.split("\n")) {
            String[] split = ms.split("\t");
            if (split.length >= 3) {
                System.out.println(split[1].trim().toUpperCase() + "(\"" + split[1].trim() + "\",\"" + split[0] + "\")," +
                        split[3].trim().toUpperCase() + "(\"" + split[3].trim() + "\",\"" + split[2] + "\"),");
            } else {
                System.out.println(split[1]+ "(\"" + split[1].trim() + "\",\"" + split[0] + "\");" );
            }
        }
    }
}
