package com.wenjie.mesplugin.service;

import com.wenjie.mesplugin.Repository.*;
import com.wenjie.mesplugin.pojo.PageBas;
import com.wenjie.mesplugin.pojo.SsdPageElement;
import com.wenjie.mesplugin.pojo.SsdPermissionMenu;
import com.wenjie.mesplugin.pojo.SsdPermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class authOperationService  extends BatchService {

    @Autowired
    PageBasRepository pageBasRepository;

    @Autowired
    SsdPageElementRepository ssdPageElementRepository;

    @Autowired
    SsdPermissionOperationRepository ssdPermissionOperationRepository;

    @Autowired
    SsdPermissionMenuRepository ssdPermissionMenuRepository;

    @Autowired
    BatchService batchService;


    public String allowAuth(String PermissionGuid){

        try {
            if(PermissionGuid == null || PermissionGuid.length() <= 0){
                throw new RuntimeException("入参为空");
            }
            //当前权限的页面
            List<SsdPermissionMenu> ssdPermissionMenuList= ssdPermissionMenuRepository.
                    findBydeleteFlagAndPermissionGuid("N",PermissionGuid);

            //所有按钮
            List<SsdPageElement> ssdPageElementList= ssdPageElementRepository.findAll();

            List<SsdPermissionOperation> ssdPermissionOperationList=new ArrayList<>();

            for (SsdPermissionMenu ssdPermissionMenu:ssdPermissionMenuList
            ) {

                for (SsdPageElement ssdPageElement:ssdPageElementList
                ) {

                    SsdPermissionOperation ssdPermissionOperation=new SsdPermissionOperation();

                    ssdPermissionOperation.setGuid(UUID.randomUUID().toString());
                    ssdPermissionOperation.setPageGuid(ssdPermissionMenu.getMenuGuid());
                    ssdPermissionOperation.setOperationGuid(ssdPageElement.getGuid());
                    ssdPermissionOperation.setCreator("digiwin");
                    ssdPermissionOperation.setCreateTime(new Date());
                    ssdPermissionOperation.setDeleteFlag("N");
                    ssdPermissionOperation.setFactory("3000");
                    ssdPermissionOperation.setPermissionGuid(ssdPermissionMenu.getPermissionGuid());

                    ssdPermissionOperationList.add(ssdPermissionOperation);

                }
            }


            batchService.batchInsert(ssdPermissionOperationList);

        }catch (Exception e){
            return "fail";
        }

        return "success";

    }


    public String authorityPlugin(String PermissionGuid){

        try {

            if(PermissionGuid == null || PermissionGuid.length() <= 0){
                throw new RuntimeException("入参为空");
            }
            //当前权限的页面
            List<SsdPermissionMenu> ssdPermissionMenuList= ssdPermissionMenuRepository.
                    findBydeleteFlagAndPermissionGuid("N",PermissionGuid);

            //所有按钮
            List<SsdPageElement> ssdPageElementList= ssdPageElementRepository.findAll();

            List<SsdPermissionOperation> ssdPermissionOperationList=new ArrayList<>();

            for (SsdPermissionMenu ssdPermissionMenu:ssdPermissionMenuList
            ) {

                for (SsdPageElement ssdPageElement:ssdPageElementList
                ) {

                    SsdPermissionOperation ssdPermissionOperation=new SsdPermissionOperation();

                    ssdPermissionOperation.setGuid(UUID.randomUUID().toString());
                    ssdPermissionOperation.setPageGuid(ssdPermissionMenu.getMenuGuid());
                    ssdPermissionOperation.setOperationGuid(ssdPageElement.getGuid());
                    ssdPermissionOperation.setCreator("digiwin");
                    ssdPermissionOperation.setCreateTime(new Date());
                    ssdPermissionOperation.setDeleteFlag("N");
                    ssdPermissionOperation.setFactory("3000");
                    ssdPermissionOperation.setPermissionGuid(ssdPermissionMenu.getPermissionGuid());

                    ssdPermissionOperationList.add(ssdPermissionOperation);

                }
            }

            ssdPermissionOperationRepository.saveAll(ssdPermissionOperationList);

        }catch (Exception e){
            return "fail";
        }

        return "success";
     }

    public  List<SsdPageElement> findBydeleteFlag(String deleteFlag){

        return ssdPageElementRepository.findBydeleteFlag(deleteFlag);
    }

    public List<SsdPermissionOperation> authorizeBtn(){

        List<PageBas> pageBass= pageBasRepository.findAll();
        List<SsdPageElement> ssdPageElements= ssdPageElementRepository.findAll();

        List<SsdPermissionOperation> ssdPermissionOperations=new ArrayList<>();


        for (PageBas pageBas:pageBass) {

            for (SsdPageElement ssdPageElement: ssdPageElements) {
                SsdPermissionOperation ssdPermissionOperation=new SsdPermissionOperation();

                ssdPermissionOperation.setGuid(UUID.randomUUID().toString());
                ssdPermissionOperation.setPageGuid(pageBas.getGuid());
                ssdPermissionOperation.setOperationGuid(ssdPageElement.getGuid());
                ssdPermissionOperation.setCreator("admin");
                ssdPermissionOperation.setCreateTime(new Date());
                ssdPermissionOperation.setDeleteFlag("N");
                ssdPermissionOperation.setFactory("3000");
                ssdPermissionOperation.setPermissionGuid("9d8af325-339c-4bbe-a7fb-671490fdc5c2");

                ssdPermissionOperations.add(ssdPermissionOperation);
            }

        }

        return ssdPermissionOperationRepository.saveAll(ssdPermissionOperations);
    }
}
