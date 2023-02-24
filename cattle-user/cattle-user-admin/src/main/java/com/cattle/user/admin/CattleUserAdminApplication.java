package com.cattle.user.admin;


import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.cattle.user.admin.mapper")
public class CattleUserAdminApplication {

    public static void main(String[] args) {
        SpringApplication.run(CattleUserAdminApplication.class,args);
    }
}
