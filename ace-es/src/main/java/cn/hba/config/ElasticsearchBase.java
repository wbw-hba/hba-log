package cn.hba.config;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import cn.hutool.setting.dialect.Props;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.client.PreBuiltTransportClient;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * es 配置初始化
 *
 * @author wbw
 * @date 2019/11/4 14:16
 */
@Slf4j
public class ElasticsearchBase {
    /**
     * 初始化 带权限登录 es client
     *
     * @return TransportClient
     */
    public RestClient authInit() {


        try {
            Props props = new Props(ElasticsearchConstant.AUTH_ES);
            log.info(props.toString());
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(AuthScope.ANY,
                    new UsernamePasswordCredentials(
                            props.getStr(ElasticsearchConstant.USERNAME), props.getStr(ElasticsearchConstant.PASSWORD)));
            String addrMap = props.getStr(ElasticsearchConstant.ADDR_MAP);
            AtomicInteger i = new AtomicInteger(0);
            JSONObject object = JSONUtil.parseObj(addrMap);
            HttpHost[] hosts = new HttpHost[object.size()];
            object.forEach((k, v) -> hosts[i.getAndIncrement()] = (new HttpHost(k, NumberUtil.parseInt(String.valueOf(v)))));
            // 该方法接收HttpAsyncClientBuilder的实例作为参数，对其修改后进行返回
            RestClientBuilder builder = RestClient.builder(hosts).setHttpClientConfigCallback(build -> {
                //提供一个默认凭据
                return build.setDefaultCredentialsProvider(credentialsProvider);
            });
            return builder.build();
        } catch (Exception e) {
            log.error("加载es集群配置失败", e);
        }
        return null;
    }

    /**
     * 初始化普通es
     *
     * @return TransportClient
     */
    public TransportClient esInit() {
        try {
            Settings.Builder builder = Settings.builder();
            JSONObject addr = this.loadEsProp(builder, ElasticsearchConstant.ES);
            TransportClient transportClient = new PreBuiltTransportClient(builder.build());
            addr.forEach((ip, port) -> {
                try {
                    transportClient.addTransportAddress(
                            new TransportAddress(InetAddress.getByName(ip), NumberUtil.parseInt(String.valueOf(port))));
                } catch (UnknownHostException e) {
                    log.error("加载es集群地址失败", e);
                }
            });
            return transportClient;
        } catch (Exception e) {
            log.error("加载es集群配置失败", e);
        }
        return null;
    }

    /**
     * 加载elasticsearch.properties 配置
     *
     * @param builder Settings.Builder
     */
    private JSONObject loadEsProp(Settings.Builder builder, String pro) {
        Props prop = Props.getProp(pro);
        if (prop.containsKey(ElasticsearchConstant.NAME)) {
            builder.put(ElasticsearchConstant.NAME, prop.getStr(ElasticsearchConstant.NAME));
        }
        if (prop.containsKey(ElasticsearchConstant.SNIFF)) {
            builder.put(ElasticsearchConstant.SNIFF, prop.getBool(ElasticsearchConstant.SNIFF, true));
        }
        if (prop.containsKey(ElasticsearchConstant.INTERVAL)) {
            builder.put(ElasticsearchConstant.INTERVAL, prop.getInt(ElasticsearchConstant.INTERVAL, 5));
        }
        if (prop.containsKey(ElasticsearchConstant.TIMEOUT)) {
            builder.put(ElasticsearchConstant.TIMEOUT, prop.getInt(ElasticsearchConstant.TIMEOUT, 5));
        }
        if (prop.containsKey(ElasticsearchConstant.IGNORE)) {
            builder.put(ElasticsearchConstant.IGNORE, prop.getBool(ElasticsearchConstant.IGNORE, true));
        }
        String addrStr = prop.getStr(ElasticsearchConstant.ADDR_MAP);
        return JSONUtil.parseObj(addrStr);
    }
}
