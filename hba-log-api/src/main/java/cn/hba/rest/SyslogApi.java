package cn.hba.rest;

import cn.hba.service.SyslogReceptionService;
import cn.hba.util.BaseResponse;
import cn.hba.util.ClientUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * syslog api 接口
 *
 * @author wbw
 * @date 2019/11/5 9:19
 */
@RestController
@Slf4j
public class SyslogApi {

    private final SyslogReceptionService receptionService;

    @Autowired
    public SyslogApi(SyslogReceptionService receptionService) {
        this.receptionService = receptionService;
    }

    /**
     * 接收syslog对象
     *
     * @param json json对象
     * @return BaseResponse
     */
    @PostMapping("/cn/hba/syslog/api")
    public BaseResponse reception(@RequestBody String json, HttpServletRequest request) {
        if (!receptionService.disSyslog(json, ClientUtil.getClientIp(request))) {
            return new BaseResponse(400, "Not valid data!");
        }
        return new BaseResponse(200, "ok");
    }
}
