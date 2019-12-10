#!/bin/bash
chmod 777 *
chmod 777 ./bin/*
chmod 777 ./conf/*
chmod 777 ./lib/*
./bin/flume-ng agent --conf ./conf --conf-file ./conf/conf.properties --name agent &
