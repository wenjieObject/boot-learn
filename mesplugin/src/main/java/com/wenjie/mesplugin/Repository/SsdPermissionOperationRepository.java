package com.wenjie.mesplugin.Repository;

import com.wenjie.mesplugin.pojo.SsdPermissionMenu;
import com.wenjie.mesplugin.pojo.SsdPermissionOperation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SsdPermissionOperationRepository extends JpaRepository<SsdPermissionOperation,String> {

    List<SsdPermissionOperation> findBydeleteFlag(String deleteFlag);
}
