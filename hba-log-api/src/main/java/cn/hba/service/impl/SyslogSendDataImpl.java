package cn.hba.service.impl;

import cn.hba.service.SyslogSendData;
import cn.hutool.core.thread.ThreadFactoryBuilder;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONUtil;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Override
    public void send(JSONArray array) {

        pool.execute(() -> array.forEach(e -> kafkaProducer.send(JSONUtil.parseObj(e).getStr("log_type").split("_")[0], array.toString())));
    }
}
