package cn.hba.es.service;

import cn.hba.es.config.EsBase;
import cn.hba.es.dto.EsDto;
import lombok.extern.log4j.Log4j2;
import org.apache.http.StatusLine;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.common.UUIDs;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * es 工具类
 *
 * @author wbw
 * @date 2019/12/10 14:32
 */
@Service
@Log4j2
public class EsService {

    private RestClient client;

    @Autowired
    public EsService(EsBase esBase) {
        client = esBase.init();
    }

    /**
     * 执行方法
     *
     * @param method   请求方法 GET、POST、DELETE、PUT
     * @param endpoint 请求的路径
     * @param json     请求体，可以为null
     * @return List<EsDto>
     */
    public List<EsDto> execute(String method, String endpoint, String json) {
        Request request = new Request(method, endpoint);
        if (json != null) {
            request.setJsonEntity(json);
        }
        List<EsDto> list = new LinkedList<>();
        try {
            Arrays.stream(EntityUtils.toString(client.performRequest(request).getEntity()).split("\n")).forEach(e -> list.add(new EsDto(e)));
        } catch (IOException e) {
            log.error(e);
        }
        return list;
    }

    /**
     * 添加数据
     *
     * @param endpoint 请求的路径
     * @param json     请求体
     */
    public void add(String endpoint, String json) {
        Request request = new Request("put", endpoint);
        request.setJsonEntity(json);
        try {
            StatusLine statusLine = client.performRequest(request).getStatusLine();
            int code = statusLine.getStatusCode();
            if (code != 200) {
                log.warn(statusLine.getReasonPhrase());
            }
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * 添加数据
     *
     * @param index 索引
     * @param type  类型
     * @param json  数据
     */
    public void add(String index, String type, String json) {
        this.add(index + "/" + type + "/" + UUIDs.base64UUID(), json);
    }
}
