package cn.hba.service.impl;

import cn.hba.constant.SyslogCommonConstant;
import cn.hba.en.event.type.*;
import cn.hba.en.log.type.LogTypeEnum;
import cn.hba.service.SyslogReceptionService;
import cn.hba.service.SyslogSendData;
import cn.hba.vo.SyslogCommonVO;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


/**
 * impl
 *
 * @author wbw
 * @date 2019/11/5 9:28
 */
@Service
@Slf4j
public class SyslogReceptionServiceImpl implements SyslogReceptionService {
    private static final String JSON_ARRAY_FORMAT = "[%s]";

    @Autowired
    private SyslogSendData sendData;

    @Override
    public boolean disSyslog(String o, String ip) {
        String v = StrUtil.str(String.valueOf(o));
        if (StrUtil.isBlank(v) || !JSONUtil.isJson(v)) {
            return false;
        }
        if (JSONUtil.isJsonObj(v)) {
            v = String.format(JSON_ARRAY_FORMAT, v);
        }
        JSONArray array = this.checkJson(JSONUtil.parseArray(v), ip);
        if (array.size() > 0) {
            sendData.send(array);
            log.info("接收数据,效验通过:\t\n{}", v);
        } else {
            log.warn("接收数据,效验未通过:\t\n{}", v);
        }
        return array.size() > 0;
    }

    /**
     * 检查 json
     *
     * @param array 数组
     * @param ip    真实ip
     * @return JSONArray
     */
    private JSONArray checkJson(JSONArray array, String ip) {
        JSONArray jsonArray = JSONUtil.createArray();
        array.forEach(e -> {
            if (!JSONUtil.isJsonObj(String.valueOf(e))) {
                jsonArray.clear();
                return;
            }
            JSONObject object = this.versifyCommon(JSONUtil.parseObj(e));
            if (object == null) {
                jsonArray.clear();
                return;
            }
            object.put(SyslogCommonConstant.FACILITY_IP, ip);
            jsonArray.put(object);
        });
        return jsonArray;
    }

    /**
     * 公共验证
     *
     * @param o JSONObject
     * @return SyslogCommonVO
     */
    private JSONObject versifyCommon(JSONObject o) {
        // key 驼峰统一转为小写
        o = this.jsonKeyToLowerCase(o);
        // 验证必要的key是否存在
        if (!this.isJsonNan(o)) {
            return null;
        }
        // 设置公共字段属性值
        SyslogCommonVO vo = this.setSyslogCommonVO(o);
        // 验证必要字段的值是否有效
        if (vo == null || !this.isCommonNan(vo) || !this.checkLogType(vo)
                || !this.isSystemAndModuleTypeValid(vo.getSystemType(), vo.getModuleType())) {
            return null;
        }
        return o;
    }

    private static final String FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

    /**
     * 设置 SyslogCommonVO 值
     *
     * @param o SyslogCommonVO
     * @return SyslogCommonVO
     */
    private SyslogCommonVO setSyslogCommonVO(JSONObject o) {

        SyslogCommonVO vo = new SyslogCommonVO();
        vo.setSyslog(o.getStr(SyslogCommonConstant.SYSLOG));
        if (NumberUtil.isNumber(o.getStr(SyslogCommonConstant.LOG_LEVEL))) {
            vo.setLogLevel(o.getInt(SyslogCommonConstant.LOG_LEVEL));
        }
        vo.setLogType(o.getStr(SyslogCommonConstant.LOG_TYPE));
        vo.setEventType(o.getStr(SyslogCommonConstant.EVENT_TYPE));
        vo.setManufacturersName(o.getStr(SyslogCommonConstant.MANUFACTURERS_NAME));
        vo.setManufacturersFacility(o.getStr(SyslogCommonConstant.MANUFACTURERS_FACILITY));
        vo.setFacilityType(o.getStr(SyslogCommonConstant.FACILITY_TYPE));
        vo.setLogDes(o.getStr(SyslogCommonConstant.LOG_DES));
        vo.setCenterTime(DateUtil.now());
        if (o.containsKey(SyslogCommonConstant.SYSTEM_TYPE)) {
            vo.setSystemType(o.getStr(SyslogCommonConstant.SYSTEM_TYPE));
        }
        if (o.containsKey(SyslogCommonConstant.MODULE_TYPE)) {
            vo.setModuleType(o.getStr(SyslogCommonConstant.MODULE_TYPE));
        }
        try {
            String eventTime = o.getStr(SyslogCommonConstant.EVENT_TIME);
            try {
                vo.setEventTime(DateUtil.parseDateTime(eventTime).toString(FORMAT));
            } catch (Exception e) {
                vo.setEventTime(DateUtil.parse(eventTime).toString(FORMAT));
            }
            return vo;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 检查 日志类型是否合格
     *
     * @param vo SyslogCommonVO
     * @return false or true
     */
    private boolean checkLogType(SyslogCommonVO vo) {
        try {
            LogTypeEnum logTypeEnum = LogTypeEnum.valueOf(vo.getLogType().toUpperCase().split("_")[0]);
            String eventType = vo.getEventType().toUpperCase();
            switch (logTypeEnum.getKey()) {
                case "attack":
                    AttackEnum.valueOf(eventType);
                    break;
                case "menace":
                    MenaceEnum.valueOf(eventType);
                    break;
                case "sysrun":
                    SysrunEnum.valueOf(eventType);
                    break;
                case "security":
                    SecurityEnum.valueOf(eventType);
                    break;
                case "network":
                    NetworkEnum.valueOf(eventType);
                    break;
                case "flow":
                    FlowEnum.valueOf(eventType);
                    break;
                case "strategy":
                    StrategyEnum.valueOf(eventType);
                    break;
                case "opconf":
                    OpconfEnum.valueOf(eventType);
                    break;
                case "hardware":
                    HardwareEnum.valueOf(eventType);
                    break;
                case "operation":
                    OperationEnum.valueOf(eventType);
                    break;
                case "other":
                    OtherEnum.valueOf(eventType);
                    break;
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * json key转为小写
     *
     * @param o JSONObject
     * @return JSONObject
     */
    private JSONObject jsonKeyToLowerCase(JSONObject o) {
        JSONObject object = new JSONObject(o.size(), false);
        o.forEach((k, v) -> object.put(StrUtil.toUnderlineCase(k), v));
        return object;
    }

    /**
     * 验证 json 是否传入必备字段
     *
     * @param o JSONObject
     * @return flag
     */
    private boolean isJsonNan(JSONObject o) {
        return o.containsKey(SyslogCommonConstant.SYSLOG) && o.containsKey(SyslogCommonConstant.LOG_LEVEL) &&
                o.containsKey(SyslogCommonConstant.LOG_TYPE) && o.containsKey(SyslogCommonConstant.EVENT_TYPE) &&
                o.containsKey(SyslogCommonConstant.MANUFACTURERS_NAME) && o.containsKey(SyslogCommonConstant.MANUFACTURERS_FACILITY) &&
                o.containsKey(SyslogCommonConstant.FACILITY_TYPE) && o.containsKey(SyslogCommonConstant.LOG_DES) &&
                o.containsKey(SyslogCommonConstant.EVENT_TIME);
    }

    /**
     * 必备字段是否有效
     *
     * @param vo SyslogCommonVO
     * @return flag
     */
    private boolean isCommonNan(SyslogCommonVO vo) {
        return StrUtil.isNotBlank(vo.getSyslog()) && !ObjectUtil.isNull(vo.getLogLevel())
                && StrUtil.isNotBlank(vo.getLogType()) && StrUtil.isNotBlank(vo.getLogDes())
                && StrUtil.isNotBlank(vo.getEventType()) && StrUtil.isNotBlank(vo.getManufacturersName())
                && StrUtil.isNotBlank(vo.getManufacturersFacility()) && StrUtil.isNotBlank(vo.getFacilityType())
                && StrUtil.isNotBlank(vo.getEventTime());

    }

    /**
     * 检查 系统类型 与 模块类型 是否有效
     *
     * @param system 系统类型
     * @param module 模块类型
     * @return boolean
     */
    private boolean isSystemAndModuleTypeValid(String system, String module) {
        return ("system".equalsIgnoreCase(system) && "safe".equalsIgnoreCase(module))
                || ("audit".equalsIgnoreCase(system) && "yunwei".equalsIgnoreCase(module));
    }
}
