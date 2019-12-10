package cn.hba.audit.flume.interceptor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * @author ikas
 */
public class JsonEventConverter {
    private ObjectMapper mapper;

    private volatile static JsonEventConverter ins = null;

    public static JsonEventConverter get() {
        if (null == ins) {
            synchronized (JsonEventConverter.class) {
                if (null == ins) {
                    ins = new JsonEventConverter();
                    ins.init();
                }
            }
        }
        return ins;
    }

    public void init() {
        mapper = new ObjectMapper();
        mapper.setPropertyNamingStrategy(PropertyNamingStrategy.LOWER_CAMEL_CASE);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE, false);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        mapper.setDateFormat(fmt);
    }

    public byte[] convert(Object object) {
        byte[] data;
        try {
            data = mapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return data;
    }


}
