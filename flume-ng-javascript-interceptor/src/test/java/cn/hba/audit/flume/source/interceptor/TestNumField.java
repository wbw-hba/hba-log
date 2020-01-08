package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.soc.SyslogParseChannels;

public class TestNumField {
    public static void main(String[] args) {
        System.out.println(SyslogParseChannels.numFiled().toString());
    }
}
