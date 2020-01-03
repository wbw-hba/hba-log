package cn.hba.api;

import cn.hba.service.EsCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * es api cache
 *
 * @author wbw
 * @date 2020/1/3 9:45
 */
@RestController
public class EsAllCacheApi {

    private final EsCacheService cacheService;

    @Autowired
    public EsAllCacheApi(EsCacheService cacheService) {
        this.cacheService = cacheService;
    }

    @PostMapping("/es-client")
    public Object esCache(@RequestBody String json) {
        return cacheService.cache(json);
    }
}
