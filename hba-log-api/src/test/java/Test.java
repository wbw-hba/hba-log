import cn.hba.en.log.type.LogTypeEnum;
import cn.hba.vo.SyslogCommonVO;
import cn.hutool.core.codec.Base64;

/**
 * @author wbw
 * @date 2019/11/5 9:46
 */
public class Test {

    @org.junit.Test
    public void test01() {

        String str = "4d:69:63:72:6f:73:6f:66:74:20:4f:66:66:69:63:65:20:d7:a8:d2:b5:d4:f6:c7:bf:b0:e6:20:32:30:31:36:20";
        System.out.println(str.replaceAll(":", ""));
        System.out.println(str.replaceAll(":", " "));
    }

    @org.junit.Test
    public void test02() {
        SyslogCommonVO vo = new SyslogCommonVO();
        vo.setLogType("xxx");
        System.out.println(checkLogType(vo));
    }


    private boolean checkLogType(SyslogCommonVO vo) {
        try {
            LogTypeEnum.valueOf(vo.getLogType().toUpperCase());
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @org.junit.Test
    public void baseCharacter(){
        String ssssss = Base64.encode("中国国情xxx124");
        System.out.println(ssssss);
        System.out.println(Base64.decodeStr(ssssss));
    }
}
