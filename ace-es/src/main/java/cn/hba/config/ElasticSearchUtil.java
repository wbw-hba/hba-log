package cn.hba.config;


import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HttpStatus;
import lombok.extern.slf4j.Slf4j;
import org.elasticsearch.action.admin.cluster.state.ClusterStateResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexResponse;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.delete.DeleteRequestBuilder;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.metrics.avg.Avg;
import org.elasticsearch.search.aggregations.metrics.avg.AvgAggregationBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * ES工具类
 *
 * @author wufei
 * @date 2017/12/26 下午2:07:06
 */
@Slf4j
public class ElasticSearchUtil {


    public static class Builder {

        public TransportClient client;

        public Builder(TransportClient client) {
            this.client = client;
        }

        /**
         * 查看集群信息
         */
        public List<DiscoveryNode> getClusterInfo() {
            List<DiscoveryNode> nodes = client.connectedNodes();
            for (DiscoveryNode node : nodes) {
                log.debug("地址: {},端口: {},主机名称: {},Id: {},版本: {}", node.getAddress().getAddress()
                        , node.getAddress().getPort(), node.getHostName(), node.getId(), node.getVersion());
            }
            return nodes;
        }

        /**
         * 新建索引
         *
         * @param indexName 索引名
         */
        public void createIndex(String indexName) {
            try {
                if (verifyIndexExist(indexName)) {
                    log.info("索引已存在: {}", indexName);
                    return;
                }
                CreateIndexResponse cIndexResponse = client.admin().indices()
                        .create(new CreateIndexRequest(indexName)).actionGet();
                if (cIndexResponse.isAcknowledged()) {
                    log.info("索引创建成功: {}", indexName);
                } else {
                    log.info("索引创建失败: {}", indexName);
                }
            } catch (Exception e) {
                log.error("索引创建失败", e);
            }
        }

        /**
         * 新建索引
         *
         * @param index 索引名
         * @param type  类型
         */
        public void createIndex(String index, String type) {
            try {
                if (verifyIndexExist(index)) {
                    log.info("索引已存在: {}", index);
                    return;
                }
                client.prepareIndex(index, type).setSource().get();
                log.info("索引创建成功: {}/{}", index, type);
            } catch (Exception e) {
                log.error("索引创建失败", e);
            }
        }

        /**
         * 删除索引
         *
         * @param index 索引名
         */
        public void deleteIndex(String index) {
            try {
                if (verifyIndexExist(index)) {
                    DeleteIndexResponse dResponse = client.admin().indices().prepareDelete(index)
                            .execute().actionGet();
                    if (dResponse.isAcknowledged()) {
                        log.info("删除索引成功：{}", index);
                    }
                    return;
                }
                log.info("索引不存在: {}，删除失败", index);
            } catch (Exception e) {
                log.error("删除索引失败", e);
            }
        }

        /**
         * 验证索引是否存在
         *
         * @param index 索引名
         */
        public boolean verifyIndexExist(String index) {
            if (StrUtil.isBlank(index)) {
                return true;
            }
            IndicesExistsRequest inExistsRequest = new IndicesExistsRequest(index);
            IndicesExistsResponse inExistsResponse = client.admin().indices().exists(inExistsRequest).actionGet();
            return inExistsResponse.isExists();
        }

        /**
         * 插入数据
         *
         * @param index 索引名
         * @param type  类型
         * @param json  数据
         */
        public void insertData(String index, String type, String json) {
            try {
                IndexResponse response = client.prepareIndex(index, type).setSource(json).get();
                int status = response.status().getStatus();
                if (status != 200) {
                    log.warn("插入数据失败:{}", index);
                } else {
                    log.debug("插入数据成功:{}", index);
                }
            } catch (Exception e) {
                log.error("插入数据失败", e);
            }
        }

        /**
         * 获取所有的索引
         */
        public List<String> getAllIndex() {
            ClusterStateResponse response = client.admin().cluster().prepareState().execute().actionGet();
            //获取所有索引
            String[] index = response.getState().getMetaData().getConcreteAllIndices();
            log.debug("索引总数为: {}", index.length);
            return CollUtil.newArrayList(index);
        }

        /**
         * 通过prepareIndex增加文档，参数为json字符串
         *
         * @param index 索引名
         * @param type  类型
         * @param id    数据id
         * @param json  数据
         */
        public void insertData(String index, String type, String id, String json) {
            try {
                IndexResponse indexResponse = client.prepareIndex(index, type).setId(id).setSource(json).get();
                if (indexResponse.status().getStatus() != 200) {
                    log.warn("插入数据失败:{}", index);
                } else {
                    log.debug("插入数据成功", index);
                }
            } catch (Exception e) {
                log.error("插入数据失败", e);
            }
        }

        /**
         * 更新数据
         *
         * @param index 索引名
         * @param type  类型
         * @param id    数据id
         * @param json  数据
         */
        public void updateData(String index, String type, String id, String json) {
            try {
                UpdateRequest updateRequest = new UpdateRequest(index, type, id).doc(json);
                UpdateResponse updateResponse = client.update(updateRequest).get();
                if (updateResponse.getGetResult().isExists()) {
                    log.debug("更新数据成功:{}", index);
                    return;
                }
                log.debug("更新数据失败:{}", index);
            } catch (Exception e) {
                log.error("更新数据失败", e);
            }
        }

        /**
         * 删除指定数据
         *
         * @param index 索引名
         * @param type  类型
         * @param id    数据id
         */
        public void deleteData(String index, String type, String id) {
            try {
                DeleteResponse response = client.prepareDelete(index, type, id).get();
                if (response.status().getStatus() != HttpStatus.HTTP_OK) {
                    log.debug("删除数据成功:{}", index);
                    return;
                }
                log.debug("删除数据失败:{}", index);
            } catch (Exception e) {
                log.error("删除数据失败", e);
            }
        }

        /**
         * 删除索引类型表所有数据，批量删除
         *
         * @param index 索引
         * @param type  类型
         */
        public void deleteIndexTypeAllData(String index, String type) {
            try {
                SearchResponse response = client.prepareSearch(index).setTypes(type)
                        .setQuery(QueryBuilders.matchAllQuery()).setSearchType(SearchType.DFS_QUERY_THEN_FETCH)
                        .setScroll(new TimeValue(60000)).setSize(10000).setExplain(false).execute().actionGet();
                BulkRequestBuilder bulkRequest = client.prepareBulk();
                while (true) {
                    SearchHit[] hitArray = response.getHits().getHits();
                    SearchHit hit;
                    for (SearchHit documentFields : hitArray) {
                        hit = documentFields;
                        DeleteRequestBuilder request = client.prepareDelete(index, type, hit.getId());
                        bulkRequest.add(request);
                    }
                    BulkResponse bulkResponse = bulkRequest.execute().actionGet();
                    if (bulkResponse.hasFailures()) {
                        log.error(bulkResponse.buildFailureMessage());
                    }
                    if (hitArray.length == 0) {
                        break;
                    }
                    response = client.prepareSearchScroll(response.getScrollId())
                            .setScroll(new TimeValue(60000)).execute().actionGet();
                }
                log.debug("批量删除索引数据成功: {}", index);
            } catch (Exception e) {
                log.error("批量删除失败", e);
            }
        }

        /**
         * 批量插入数据
         *
         * @param index    索引名
         * @param type     类型
         * @param jsonList 批量数据
         */
        public void bulkInsertData(String index, String type, List<String> jsonList) {
            try {
                BulkRequestBuilder bulkRequest = client.prepareBulk();
                jsonList.forEach(item -> bulkRequest.add(client.prepareIndex(index, type).setSource(item)));
                BulkResponse bulkResponse = bulkRequest.get();
                if (!bulkResponse.hasFailures()) {
                    log.debug("批量插入成功: {}", bulkResponse.getItems().length);
                } else {
                    log.debug("批量插入失败:{}", index);
                }
            } catch (Exception e) {
                log.error("批量插入失败", e);
            }

        }

        /**
         * 通过prepareGet方法获取指定文档信息
         */
        public String getOneDocument(String index, String type, String id) {
            // 搜索数据
            GetResponse response = client.prepareGet(index, type, id).get();
            return response.getSourceAsString();
        }

        /**
         * 通过prepareSearch方法获取指定索引所有文档信息
         */
        public List<Map<String, Object>> getDocuments(String index) {
            List<Map<String, Object>> mapList = new ArrayList<>();
            // 搜索数据
            SearchResponse response = client.prepareSearch(index)
//    			.setTypes("type1","type2"); //设置过滤type
//    			.setTypes(SearchType.DFS_QUERY_THEN_FETCH)  精确查询
//    			.setQuery(QueryBuilders.matchQuery(term, queryString));
//    			.setFrom(0) //设置查询数据的位置,分页用
//    			.setSize(60) //设置查询结果集的最大条数
//    			.setExplain(true) //设置是否按查询匹配度排序
                    .get(); //最后就是返回搜索响应信息
            SearchHit[] hits = response.getHits().getHits();
            for (SearchHit hit : hits) {
                mapList.add(hit.getSourceAsMap());
            }
            return mapList;
        }

        /**
         * 获取指定索引库下指定type所有文档信息
         *
         * @param index 索引
         * @param type  类型
         * @return List<Map < String, Object>>
         */
        public List<Map<String, Object>> getDocuments(String index, String type) {
            List<Map<String, Object>> mapList = new ArrayList<>();
            SearchResponse response = client.prepareSearch(index).setTypes(type).get();
            SearchHit[] hits = response.getHits().getHits();
            for (SearchHit hit : hits) {
                Map<String, Object> source = hit.getSourceAsMap();
                mapList.add(source);
            }
            return mapList;
        }

        /**
         * 读取索引类型表指定列名的平均值
         *
         * @param avgField 聚合字段
         * @return double
         */
        public double readIndexTypeFieldValueWithAvg(String index, String type, String avgField) {
            String avgName = avgField + "Avg";
            AvgAggregationBuilder aggregation = AggregationBuilders.avg(avgName).field(avgField);
            SearchResponse response = client.prepareSearch(index).setTypes(type)
                    .setQuery(QueryBuilders.matchAllQuery())
                    .addAggregation(aggregation).execute().actionGet();
            Avg avg = response.getAggregations().get(avgName);
            return avg.getValue();
        }

        /**
         * 关闭链接
         */
        public void close() {
            client.close();
        }
    }
}