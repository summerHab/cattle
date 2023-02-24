package com.cattle.user.admin.service.impl;


import com.auth.common.core.exception.Oauth2RegisteredClientNotException;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.cattle.user.admin.mapper.RegisteredClientMapper;
import com.cattle.user.admin.mapper.entity.RegisteredClientEntity;
import com.cattle.user.admin.service.RegisteredClientService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;


@Service
@Slf4j
public class RegisteredClientServiceImpl extends ServiceImpl<RegisteredClientMapper, RegisteredClientEntity> implements RegisteredClientService {


    /***
     * 查询  Oauth2RegisteredClient
     * @param clientId
     * @return
     */
    public RegisteredClientEntity findByClientId(String clientId) throws Exception {
        RegisteredClientEntity oauth2RegisteredClient = this.baseMapper.selectByClientId(clientId);
        if (oauth2RegisteredClient == null) {
            log.error("clientId not exist!");
            throw new Oauth2RegisteredClientNotException("clientId not exist!");
        }
        return oauth2RegisteredClient;
    }
}
