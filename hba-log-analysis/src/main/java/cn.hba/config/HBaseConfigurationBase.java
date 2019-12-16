package cn.hba.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

/**
 * HBase 基础配置
 *
 * @author wbw
 * @date 2019/12/9 13:07
 */
@org.springframework.context.annotation.Configuration
@Slf4j
@Data
public class HBaseConfigurationBase {

    @Value("${hbase.zookeeper.quorum}")
    private String quorum;

    /**
     * 产生 HBaseConfiguration 实例化 Bean
     *
     * @return Configuration
     */
    @Bean
    public Configuration configuration() {
        Configuration conf = HBaseConfiguration.create();
        conf.set("hbase.zookeeper.quorum", quorum);
        conf.set("hbase.defaults.for.version.skip", "true");

        log.info("hbase.zookeeper.quorum is:\t{}", quorum);
        return conf;
    }
}
