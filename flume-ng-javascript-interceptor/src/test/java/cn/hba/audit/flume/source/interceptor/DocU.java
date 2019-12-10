package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.soc.SyslogParseChannels;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * @author wbw
 * @date 2019/11/28 17:29
 */
public class DocU {

    public static void main(String[] args) {
        String body = "{\"Priority\":\"6\",\"host\":\"[127, 0, 0, 1]\",\"Severity\":\"6\",\"Facility\":\"0\",\"syslog\":" +
                "\"<188>Dec 4 11:13:37 SecOS 2019-12-04 11:13:37 WAF: 192.168.6.154:11788->59.255.22.68 dip=192.168.109.99 devicename=SecOS url=/audit-web/rest/epointqlk/audititem/tasktype/xzxk/audititemdetailaction/page_load method=POST args=taskguid=7c34ff26-eed0-4254-8c80-d4adec295e57&changeOrModify=null&isCommondto=true&MmEwMD=45zLje8wDUzZQ7NZBUNK8qNvn_ZJtwm1gRCIxGnDFqeTm62duDPRfEM_FFYyZpt0TvsmOXOPA32Yzex_mkDvvOnO9EX1HwF0h3pOTAthUns3YcseWJCI7aSF7lN5YUsZ_Kuqw_Ex6z8WUdNlKWMNe4JDKMDc9Awnux_UOxZAgxjc0oGU3nco40F8k8luQ2aph0mo2V74FtSNhVM6l9hbzNklxCIXy3SZs_PJtHD9I8wipbKOpM9CFYCXFHJP4LYndHgCHpy4fQf.FsuHRaz5f3B.3KjvxlMFDwCP5iF5XSdKmcA7DBr2YqWq41hvX7_Vzsm76I0MblHnabBSijSUPc0ISlt8H7_Gc.eLm8RCuazgNXr flag_field= block_time=0 http_type= attack_field=1 profile_id=6 rule_id=30041 type=Signature Rule severity=0 action=CONTINUE referer= useragent= post= equipment=2 os=8 browser=0 |\"}";
        Map<String,String> map = new HashMap<>();
        map.put("facility_ip","127.0.0.1");
        Object dispose = new SyslogParseChannels().dispose(map, body);
        System.out.println(JSONUtil.parse(dispose).toJSONString(2));
    }
}
