package com.cattle.user.admin.service;


import com.cattle.user.admin.mapper.entity.RegisteredClientEntity;

/***
 * oauth2_registered_client 服务
 * @author byh
 * @date 2023-02-21
 */
public interface RegisteredClientService {

    /***
     * 查询 clientId 信息
     * @param clientId
     * @return
     */
    RegisteredClientEntity findByClientId(String clientId) throws Exception;
}
