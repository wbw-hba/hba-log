package cn.hba.util;

import lombok.Data;

/**
 * 基础响应类
 *
 * @author wbw
 * @date 2019年12月9日15:50:25
 */
@Data
public class BaseResponse {
    private int status = 200;
    private String message;

    public BaseResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }
}
