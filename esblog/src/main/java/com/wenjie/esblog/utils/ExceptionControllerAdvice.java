package com.wenjie.esblog.utils;

import com.wenjie.esblog.pojo.APIException;
import com.wenjie.esblog.pojo.ResultCode;
import com.wenjie.esblog.pojo.ResultVO;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionControllerAdvice {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResultVO<String> MethodArgumentNotValidExceptionHandler(MethodArgumentNotValidException e) {
        // 从异常对象中拿到ObjectError对象
        ObjectError objectError = e.getBindingResult().getAllErrors().get(0);
        // 然后提取错误提示信息进行返回
        //return objectError.getDefaultMessage();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.VALIDATE_FAILED, objectError.getDefaultMessage());
    }

    @ExceptionHandler(APIException.class)
    public  ResultVO<String> APIExceptionHandler(APIException e) {
        //return e.getMsg();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.FAILED, e.getMsg());
    }

    @ExceptionHandler(Exception.class)
    public  ResultVO<String> ExceptionHandler(Exception e) {
        //return e.getMsg();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.FAILED, e.getMessage()+"通用异常数据");
    }

}
