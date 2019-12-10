package cn.hba.service;

import org.apache.hadoop.hbase.Cell;

import java.util.List;
import java.util.Map;

/**
 * HBase 基础服务
 *
 * @author wbw
 * @date 2019/12/9 13:28
 */
public interface HBaseService {
    /**
     * 创建表
     *
     * @param tableName 表名
     * @param families  字段
     */
    void createTable(String tableName, String... families);

    /**
     * 删除表
     *
     * @param tableName 表名
     */
    void deleteTable(String tableName);

    /**
     * 添加一行值
     *
     * @param tableName    表名
     * @param rowKey       行 key
     * @param familyColumn 字段
     * @param columnName   字段名
     * @param value        字段值
     */
    void putRowValue(String tableName, String rowKey, String familyColumn, String columnName, String value);

    /**
     * 批量添加
     *
     * @param tableName    表名
     * @param rowKey       key
     * @param familyColumn 字段
     * @param columnNames  字段名
     * @param values       字段值
     */
    void putRowValueBatch(String tableName, String rowKey, String familyColumn, List<String> columnNames, List<String> values);

    /**
     * 批量添加
     *
     * @param tableName    表名
     * @param rowKey       key
     * @param familyColumn 字段
     * @param columnValues 字段值
     */
    void putRowValueBatch(String tableName, String rowKey, String familyColumn, Map<String, String> columnValues);

    /**
     * 扫描行键 根据表名前缀
     *
     * @param tableName 表名
     * @param regexKey  key
     * @return List<Cell>
     */
    List<Cell> scanRegexRowKey(String tableName, String regexKey);

    /**
     * 删除所有字段
     *
     * @param tableName 表名
     * @param rowKey    key
     */
    void deleteAllColumn(String tableName, String rowKey);

    /**
     * 删除字段
     *
     * @param tableName  表名
     * @param rowKey     key
     * @param familyName 名称
     * @param columnName 字段名
     */
    void deleteColumn(String tableName, String rowKey, String familyName, String columnName);

}
