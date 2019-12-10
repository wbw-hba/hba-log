package cn.hba.audit.flume.interceptor;

import java.util.Map;

public interface IParser {
    Object parse(Map headers, String body, String type);
}
