package cn.hba.es.config;

import cn.hutool.core.util.NumberUtil;
import lombok.extern.log4j.Log4j2;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.client.RestClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * es基础配置类
 *
 * @author wbw
 * @date 2019/12/10 13:57
 */
@Service
@Log4j2
public class EsBase {

    @Value("${es.client.transport.sniff}")
    private Boolean sniff;
    @Value("${es.client.transport.ignore_cluster_name}")
    private Boolean ignoreClusterName;
    @Value("${es.cluster.name}")
    private String clusterName;
    @Value("${es.cluster.addr_map}")
    private String addrMap;
    @Value("${es.cluster.username}")
    private String username;
    @Value("${es.cluster.password}")
    private String password;
    @Value("${es.client.transport.nodes_sampler_interval}")
    private Integer nodesSamplerInterval;
    @Value("${es.client.transport.ping_timeout}")
    private Integer timeout;

    public RestClient init() {
        try {
            final CredentialsProvider cp = new BasicCredentialsProvider();
            cp.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));

            List<String> addrCollect = Arrays.stream(addrMap.split(",")).collect(Collectors.toList());
            AtomicInteger i = new AtomicInteger(0);
            HttpHost[] hosts = new HttpHost[addrCollect.size()];
            addrCollect.forEach(val -> {
                String[] kv = val.split(":");
                hosts[i.getAndIncrement()] = (new HttpHost(kv[0], NumberUtil.parseInt(String.valueOf(kv[1]))));
            });
            Header[] headers = new Header[]{
                    new BasicHeader("client.transport.ignore_cluster_name", String.valueOf(ignoreClusterName))
                    , new BasicHeader("cluster.name", String.valueOf(clusterName))
                    , new BasicHeader("client.transport.sniff", String.valueOf(sniff))};
            // 该方法接收HttpAsyncClientBuilder的实例作为参数，对其修改后进行返回
            return RestClient.builder(hosts).setHttpClientConfigCallback(b -> b.setDefaultCredentialsProvider(cp))
                    .setDefaultHeaders(headers).build();
        } catch (Exception e) {
            log.error("加载es集群配置失败", e.getMessage());
            throw e;
        }
    }
}
