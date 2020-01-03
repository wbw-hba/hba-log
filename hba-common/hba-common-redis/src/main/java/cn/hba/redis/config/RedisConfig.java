package cn.hba.redis.config;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.interceptor.CacheErrorHandler;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.cache.RedisCacheWriter;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * redis 全局基础配置
 * EnableCaching 开启注解
 *
 * @author 王保卫
 * @date 2018/12/15 16:41
 */
@Configuration
@Slf4j
public class RedisConfig extends CachingConfigurerSupport {

    /**
     * RedisTemplate 模板类
     *
     * @param factory redis工厂类
     * @return RedisTemplate redis模板
     **/
    @Bean
    public RedisTemplate redisTemplate(RedisConnectionFactory factory) {
        // 获取模板
        StringRedisTemplate template = new StringRedisTemplate(factory);
        // 获取序列化对象
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = getJackson();

        // 此处设置 防止 redis 序列化 不可逆，及乱码问题
        //设置序列化Key的实例化对象
        template.setValueSerializer(jackson2JsonRedisSerializer);
        //设置序列化Value的实例化对象
        template.setKeySerializer(jackson2JsonRedisSerializer);
        template.setHashKeySerializer(jackson2JsonRedisSerializer);
        template.setHashValueSerializer(jackson2JsonRedisSerializer);
        template.setDefaultSerializer(jackson2JsonRedisSerializer);
        template.setEnableDefaultSerializer(true);
        // 设置模板属性
        template.afterPropertiesSet();
        return template;
    }

    /**
     * 获取序列化字符设置
     *
     * @return 序列化字符串
     */
    private Jackson2JsonRedisSerializer<Object> getJackson() {
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer
                = new Jackson2JsonRedisSerializer<>(Object.class);
        ObjectMapper om = new ObjectMapper();
        om.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        jackson2JsonRedisSerializer.setObjectMapper(om);
        return jackson2JsonRedisSerializer;
    }


    /**
     * 二级缓存 配置
     * redisConnectionFactory 自动注入redis
     *
     * @return CacheManager 缓存
     **/
    @Bean
    public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
        return new RedisCacheManager(
                RedisCacheWriter.nonLockingRedisCacheWriter(redisConnectionFactory),
                // 默认策略，未配置的 key 会使用这个
                this.getRedisCacheConfigurationWithTtl(1800),
                // 指定 key 策略
                this.getRedisCacheConfigurationMap());
    }

    /**
     * 指定key策略
     * 获取Redis缓存配置映射
     *
     * @return Map String   , RedisCacheConfiguration
     */
    private Map<String, RedisCacheConfiguration> getRedisCacheConfigurationMap() {
        Map<String, RedisCacheConfiguration> map = new HashMap<>(2);
        // 这里时间为秒数
        map.put("UserInfoList", this.getRedisCacheConfigurationWithTtl(2000));
        map.put("UserInfoListAnother", this.getRedisCacheConfigurationWithTtl(2000));
        return map;
    }

    /**
     * 使用序列化秒数获取Redis缓存配置
     *
     * @param seconds 秒数
     * @return RedisCacheConfiguration
     */
    private RedisCacheConfiguration getRedisCacheConfigurationWithTtl(Integer seconds) {
        // 设置redis 默认配置
        RedisCacheConfiguration redisCacheConfiguration = RedisCacheConfiguration.defaultCacheConfig();
        redisCacheConfiguration = redisCacheConfiguration
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(getJackson()))
                .entryTtl(Duration.ofSeconds(seconds));

        return redisCacheConfiguration;
    }

    /**
     * 自定义生成缓存key
     *
     * @return KeyGenerator key生产者
     **/
    @Bean
    @Override
    public KeyGenerator keyGenerator() {
        return (target, method, params) -> {
            StringBuilder sb = new StringBuilder();
            // 文件名 + 方法名 + 参数名
            String name = target.getClass().getName();
            sb.append(name);
            sb.append(method.getName());
            for (Object obj : params) {
                if (obj == null) {
                    continue;
                }
                sb.append(":").append(obj.toString());
            }
            return sb;
        };
    }

    /**
     * 读取缓存时异常处理
     *
     * @return CacheErrorHandler
     */
    @Override
    @Bean
    public CacheErrorHandler errorHandler() {
        return new CacheErrorHandler() {
            @Override
            public void handleCacheGetError(RuntimeException e, Cache cache, Object key) {
                log.error("获取缓存时异常---key：-" + key + "异常信息:" + e);
            }

            @Override
            public void handleCachePutError(RuntimeException e, Cache cache, Object key, Object value) {
                log.error("handleCachePutError缓存时异常---key：-" + key + "异常信息:" + e);
            }

            @Override
            public void handleCacheEvictError(RuntimeException e, Cache cache, Object key) {
                log.error("handleCacheEvictError缓存时异常---key：-" + key + "异常信息:" + e);
            }

            @Override
            public void handleCacheClearError(RuntimeException e, Cache cache) {
                log.error("清除缓存时异常---：-" + "异常信息:" + e);
            }
        };
    }
}