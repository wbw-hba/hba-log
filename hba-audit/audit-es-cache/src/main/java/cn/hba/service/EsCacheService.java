package cn.hba.service;

import lombok.NonNull;

/**
 * es cache
 *
 * @author wbw
 * @date 2020/1/3 9:48
 */
public interface EsCacheService {

    /**
     * 缓存
     *
     * @param json 请求条件
     * @return object
     */
    Object cache(@NonNull String json);
}