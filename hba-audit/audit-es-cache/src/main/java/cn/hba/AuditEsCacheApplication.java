package cn.hba;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

/**
 * 启动程序
 *
 * @author wbw
 * @date 2020/1/3 9:39
 */
@EnableCaching
@SpringBootApplication
public class AuditEsCacheApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuditEsCacheApplication.class, args);
    }
}