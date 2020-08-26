package com.wenjie.mesplugin.controller;

import com.wenjie.mesplugin.pojo.SsdPageElement;
import com.wenjie.mesplugin.pojo.SsdPermissionOperation;
import com.wenjie.mesplugin.service.authOperationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/logger")
public class loggerController {

    @Autowired
    authOperationService authOperationService;

    @GetMapping("/get")
    public String test(){
        return  "success";
    }


    @PostMapping("/authBtn")
    public List<SsdPermissionOperation> authorizeBtn()
    {
        return authOperationService.authorizeBtn();
    }

    @GetMapping("/getdelete/{deleteFlag}")
    public  List<SsdPageElement> findBydeleteFlag(@PathVariable("deleteFlag") String deleteFlag){

        return authOperationService.findBydeleteFlag(deleteFlag);
    }

    @PostMapping("/authorityPlugin")
    public String authorityPlugin(@RequestParam("PermissionGuid") String PermissionGuid){

        return  authOperationService.allowAuth(PermissionGuid);

    }
}
