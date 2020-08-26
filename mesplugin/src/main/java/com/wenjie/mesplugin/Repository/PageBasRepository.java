package com.wenjie.mesplugin.Repository;

import com.wenjie.mesplugin.pojo.PageBas;
import com.wenjie.mesplugin.pojo.SsdPageElement;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PageBasRepository  extends JpaRepository<PageBas,String> {

    List<PageBas> findBydeleteFlag(String deleteFlag);
}
