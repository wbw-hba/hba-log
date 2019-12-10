###  说明
```
此 api 接口收集日志目前没有进行存储.
```

# 代码结构说明

```
ace-syslog
    
  constant--------------常量
   
  en-----------------枚举类
   
  rest-----------------接口

  service--------------服务

  vo------------------视图
```
### 注意
```
1.新添加必要字段 应在 event.type 下面对应类添加。 
2.本项目所有常用工具均在Hutool 都有说明，可以直接去Hutool中午文档查询使用方法。https://www.hutool.cn/docs/#/captcha/%E6%A6%82%E8%BF%B0
3.本项目遵循 阿里代码规约，同应在idea下载 Alibaba Java Coding Guidelines 插件给予开发帮助。
4.本项目依赖 lombok 插进，请在idea下载.
5.其他有需要说明应在此添加。
```