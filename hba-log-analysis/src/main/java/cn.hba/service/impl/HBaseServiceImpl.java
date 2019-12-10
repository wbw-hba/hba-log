package cn.hba.service.impl;

import cn.hba.service.HBaseService;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.Cell;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.filter.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import lombok.extern.log4j.Log4j2;

/**
 * HBase 仓库操作
 *
 * @author wbw
 * @date 2019/12/9 13:20
 */
@Service
@Log4j2
public class HBaseServiceImpl implements HBaseService {

    @Autowired
    private Configuration configuration;

    @Override
    public void createTable(String tableName, String... families) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Admin admin = connection.getAdmin()) {
            if (!admin.tableExists(TableName.valueOf(tableName))) {
                HTableDescriptor descriptor = new HTableDescriptor(TableName.valueOf(tableName));
                Arrays.stream(families).forEach(val -> descriptor.addFamily(new HColumnDescriptor(val)));
                admin.createTable(descriptor);
                log.info("Create table Successfully!!! Table Name:[" + tableName + "]");
            }
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public void deleteTable(String tableName) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Admin admin = connection.getAdmin()) {
            TableName table = TableName.valueOf(tableName);
            if (!admin.tableExists(table)) {
                return;
            }
            admin.disableTable(table);
            admin.deleteTable(table);
            log.info("delete table " + tableName + " successfully!");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public void putRowValue(String tableName, String rowKey, String familyColumn, String columnName, String value) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            Put put = new Put(Bytes.toBytes(rowKey));
            put.addColumn(Bytes.toBytes(familyColumn), Bytes.toBytes(columnName), Bytes.toBytes(value));
            table.put(put);
            log.info("update table:" + tableName + ",rowKey:" + rowKey + ",family:" + familyColumn + ",column:" + columnName + ",value:" + value + " successfully!");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public void putRowValueBatch(String tableName, String rowKey, String familyColumn, List<String> columnNames, List<String> values) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            Put put = new Put(Bytes.toBytes(rowKey));
            columnNames.forEach(e -> put.addColumn(Bytes.toBytes(familyColumn), Bytes.toBytes(e), Bytes.toBytes(values.get(columnNames.indexOf(e)))));
            table.put(put);
            log.info("update table:" + tableName + ",rowKey:" + rowKey + ",family:" + familyColumn + ",columns:" + columnNames + ",values:" + values + " successfully!");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public void putRowValueBatch(String tableName, String rowKey, String familyColumn, Map<String, String> columnValues) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            Put put = new Put(Bytes.toBytes(rowKey));
            columnValues.forEach((k, v) -> put.addColumn(Bytes.toBytes(familyColumn), Bytes.toBytes(k), Bytes.toBytes(v)));
            table.put(put);
            log.info("update table:" + tableName + ",rowKey:" + rowKey + " successfully!");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public List<Cell> scanRegexRowKey(String tableName, String regexKey) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            Scan scan = new Scan();
            scan.setFilter(new RowFilter(CompareFilter.CompareOp.EQUAL, new RegexStringComparator(regexKey)));
            return table.getScanner(scan).next().listCells();
        } catch (IOException e) {
            log.error(e.getMessage());
        }
        return null;
    }

    @Override
    public void deleteAllColumn(String tableName, String rowKey) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            table.delete(new Delete(Bytes.toBytes(rowKey)));
            log.info("Delete rowKey:" + rowKey + "'s all Columns Successfully");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public void deleteColumn(String tableName, String rowKey, String familyName, String columnName) {
        try (Connection connection = ConnectionFactory.createConnection(configuration);
             Table table = connection.getTable(TableName.valueOf(tableName))) {
            Delete delColumn = new Delete(Bytes.toBytes(rowKey));
            delColumn.addColumn(Bytes.toBytes(familyName), Bytes.toBytes(columnName));
            table.delete(delColumn);
            log.info("Delete rowKey:" + rowKey + "'s Column:" + columnName + " Successfully");
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }
}
