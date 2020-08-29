package com.wenjie.multidb.slave.repository;

import com.wenjie.multidb.slave.pojo.Teacher;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TeacherDao extends JpaRepository<Teacher,Integer> {

}
