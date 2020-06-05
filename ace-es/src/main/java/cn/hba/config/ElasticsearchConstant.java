package cn.hba.config;


import cn.hutool.system.SystemUtil;

import java.io.File;

/**
 * es 常量
 *
 * @author wbw
 * @date 2019/11/4 14:19
 */
public interface ElasticsearchConstant {
    String PROJECT_PATH = SystemUtil.get(SystemUtil.USER_DIR) + File.separator + "config" + File.separator;

    /**
     * es 配置文件
     */
    String AUTH_ES = "auth-es.properties";
    String ES = "es.properties";
    /**
     * 集群节点地址
     */
    String ADDR_MAP = "cluster.addr_map";
    /**
     * 嗅探
     */
    String SNIFF = "client.transport.sniff";
    String NAME = "cluster.name";
    String INTERVAL = "client.transport.nodes_sampler_interval";
    String TIMEOUT = "client.transport.ping_timeout";
    String IGNORE = "client.transport.ignore_cluster_name";
    String USERNAME = "cluster.username";
    String PASSWORD = "cluster.password";
    String EXCLUDE_INDEX = "exclude_index";
    String INCLUDE_INDEX = "include_index";
    String INDEX_SIZE = "index_size";
    String ES_COPY = "es-copy.properties";


}
