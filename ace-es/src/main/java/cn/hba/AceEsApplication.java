package cn.hba;

import cn.hba.crawling.EsCopyMain;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;

/**
 * 入口
 *
 * @author wbw
 * @date 2019-11-24 12:22
 */
@SpringBootApplication
public class AceEsApplication {
    public static void main(String[] args) {
        SpringApplication.run(AceEsApplication.class, args);
        try {
            new EsCopyMain().copyIndexData();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
