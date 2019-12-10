package cn.hba.es.dto;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;

/**
 * es 数据转化对象
 *
 * @author wbw
 * @date 2019/12/10 14:38
 */
@Data
public class EsDto {

    private String index;

    private String type;

    private String id;

    private Integer version;

    private Integer score;

    private JSONObject source;

    public EsDto(JSONObject object) {
        index = object.getStr("_index");
        type = object.getStr("_type");
        id = object.getStr("_id");
        version = object.getInt("_version");
        score = object.getInt("_score");
        source = object.getJSONObject("_source");
    }
    public EsDto(String json) {
        new EsDto(JSONUtil.parseObj(json));
    }
}
