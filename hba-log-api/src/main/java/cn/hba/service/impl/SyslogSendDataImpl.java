package cn.hba.service.impl;

import cn.hba.es.service.EsService;
import cn.hba.service.SyslogSendData;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.thread.ThreadFactoryBuilder;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.*;

/**
 * impl
 *
 * @author wbw
 * @date 2019/12/10 11:04
 */
@Service
public class SyslogSendDataImpl implements SyslogSendData {
    private ThreadFactory namedThreadFactory = ThreadFactoryBuilder.create().setNamePrefix(SyslogReceptionServiceImpl.class.getName()).build();
    private ExecutorService pool = new ThreadPoolExecutor(8, 8,
            3000L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(1024), namedThreadFactory, new ThreadPoolExecutor.AbortPolicy());

    @Autowired
    private KafkaTemplate<String, String> kafkaProducer;
    @Autowired
    private EsService esService;
    @Value("${app.su.es}")
    private boolean suEs;
    @Value("${app.su.kafka}")
    private boolean suKafka;

    @Override
    public void send(JSONArray array) {
        pool.execute(() -> array.forEach(e -> {
            JSONObject obj = JSONUtil.parseObj(e);
            if (suEs) {
                esService.add(this.index(obj), "doc", obj.toString());
            }
            if (suKafka) {
                kafkaProducer.send(obj.getStr("log_type").split("_")[0], obj.toString());
            }
        }));
    }

    /**
     * 获取索引
     *
     * @param obj 索引
     * @return String
     */
    private String index(JSONObject obj) {
        return obj.getStr("system_type") + "-" + obj.getStr("module_type") + "-"
                + obj.getStr("log_type").split("_")[0] + "_" + obj.getStr("event_type")
                + "-" + DateUtil.date().toDateStr();
    }
}