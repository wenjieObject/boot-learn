package com.wenjie.mesplugin.Repository;

import com.wenjie.mesplugin.pojo.SsdPageElement;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SsdPageElementRepository extends JpaRepository<SsdPageElement,String> {

    List<SsdPageElement> findBydeleteFlag(String deleteFlag);
}
