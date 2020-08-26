package com.wenjie.mesplugin.Repository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Transactional
@Service
public class BatchService {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 批量插入
     *
     * @param list 实体类集合
     * @param <T>  表对应的实体类
     */
    public <T> void batchInsert(List<T> list) {
        if (!ObjectUtils.isEmpty(list)){
            for (int i = 0; i < list.size(); i++) {
                entityManager.persist(list.get(i));
                if (i % 50 == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }
            entityManager.flush();
            entityManager.clear();
        }
    }


    /**
     * 批量更新
     *
     * @param list 实体类集合
     * @param <T>  表对应的实体类
     */
    public <T> void batchUpdate(List<T> list) {
        if (!ObjectUtils.isEmpty(list)){
            for (int i = 0; i < list.size(); i++) {
                entityManager.merge(list.get(i));
                if (i % 50 == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }
            entityManager.flush();
            entityManager.clear();
        }
    }


}
