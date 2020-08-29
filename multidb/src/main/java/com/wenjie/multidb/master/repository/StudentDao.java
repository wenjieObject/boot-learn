package com.wenjie.multidb.master.repository;

import com.wenjie.multidb.master.pojo.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentDao extends JpaRepository<Student, Integer> {


}
