package com.cattle.user.admin.mapper;


import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.cattle.user.admin.mapper.entity.RegisteredClientEntity;
import org.apache.ibatis.annotations.Param;



public interface RegisteredClientMapper extends BaseMapper<RegisteredClientEntity> {

    RegisteredClientEntity selectByClientId(@Param("clientId") String clientId);


}
