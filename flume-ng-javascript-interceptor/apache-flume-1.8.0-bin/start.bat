@echo off
TITLE hbEventAgent



echo Using JAVA_HOME: %JAVA_HOME%

set "CURRENT_DIR=%cd%"

set CLASSPATH="%CURRENT_DIR%\lib\*;%CURRENT_DIR%\conf"

echo Using CLASSPATH:%CLASSPATH%

"%JAVA_HOME%\bin\java" -Xms1512m -Xmx1512m  -server   -classpath "%CLASSPATH%"  org.apache.flume.node.Application  -f conf/conf.properties -n agent