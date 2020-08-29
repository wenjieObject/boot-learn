package com.wenjie.multidb.controller;

import com.wenjie.multidb.master.pojo.Student;
import com.wenjie.multidb.slave.pojo.Teacher;
import com.wenjie.multidb.slave.repository.TeacherDao;
import com.wenjie.multidb.master.repository.StudentDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JpaMultidbController {

    @Autowired
    private StudentDao studentDao;

    @Autowired
    private TeacherDao teacherDao;

    @GetMapping("/list")
    public void list() {
        System.out.println(studentDao.findAll());
        System.out.println(teacherDao.findAll());
    }

    @GetMapping("/add")
    @Transactional
    public String add(){
        Student student=new Student("name",12,0);

        studentDao.save(student);

        if(true){
            throw new RuntimeException("123321");
        }


        Teacher teacher=new Teacher("name","tt","cc");
        teacherDao.save(teacher);
        return "success";
    }

}
