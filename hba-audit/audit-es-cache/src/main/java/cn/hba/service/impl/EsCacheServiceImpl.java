package cn.hba.service.impl;

import cn.hba.service.EsCacheService;
import lombok.NonNull;
import org.springframework.stereotype.Service;

/**
 * impl
 *
 * @author wbw
 * @date 2020/1/3 9:52
 */
@Service
public class EsCacheServiceImpl implements EsCacheService {


    @Override
    public Object cache(@NonNull String json) {
        System.out.println(json);
        return "xxxx";
    }
}
