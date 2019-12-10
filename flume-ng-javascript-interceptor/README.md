###  说明
```
此 flume 可以对syslog进行直接解析，解析完毕的项目直接打包放在  apache-flume-1.8.0-bin/lib 即可。
需要修改 apache-flume-1.8.0-bin/conf/conf.properties 便可以直接使用.
```
##### 乱码需知
``` 乱码应重启一份flume 改为对应编码即可。```

# 代码结构说明

```
flume-ng-javascript-interceptor
    
  interceptor--------------保留
   
  soc-----------------解析中心
   
  util-----------------工具
```
### 注意
```
1.新添加产商应在soc新添加包与接口，同时在SyslogParseChannels.loadFacilityIp 加入对应产商接口。
2.本项目所有常用工具均在Hutool 都有说明，可以直接去Hutool中午文档查询使用方法。https://www.hutool.cn/docs/#/captcha/%E6%A6%82%E8%BF%B0
3.本项目遵循 阿里代码规约，同应在idea下载 Alibaba Java Coding Guidelines 插件给予开发帮助。
4.其他有需要说明应在此添加。
```

### unix环境问题
在 .sh 文件 输入 :set ff=unix  即可