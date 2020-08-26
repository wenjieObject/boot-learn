package com.wenjie.mesplugin.Repository;

import com.wenjie.mesplugin.pojo.PageBas;
import com.wenjie.mesplugin.pojo.SsdPermissionMenu;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SsdPermissionMenuRepository extends JpaRepository<SsdPermissionMenu,String> {

    List<SsdPermissionMenu> findBydeleteFlag(String deleteFlag);

    List<SsdPermissionMenu> findBydeleteFlagAndPermissionGuid(String deleteFlag,String PermissionGuid);

}
