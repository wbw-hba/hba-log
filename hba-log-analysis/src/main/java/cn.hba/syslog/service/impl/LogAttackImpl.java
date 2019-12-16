package cn.hba.syslog.service.impl;

import cn.hba.syslog.service.LogAttack;
import cn.hutool.json.JSONArray;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

/**
 * 攻击类
 *
 * @author wbw
 * @date 2019/12/16 14:45
 */
@Service
@Log4j2
public class LogAttackImpl implements LogAttack {


    @Override
    public void stream(JSONArray val) {
        log.info(val);
    }
}
