package com.cattle.user.admin.mapper.entity;


import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.util.Date;


@Data
@TableName("oauth2_registered_client")
public class RegisteredClientEntity {

    @TableId(type = IdType.ASSIGN_ID)
    public String id;
    public String clientId;
    public Date clientIdIssuedAt;
    public String clientSecret;
    public Date clientSecretExpiresAt;
    public String clientAuthenticationMethods;
    public String authorizationGrantTypes;
    public String redirectUris;
    public String scopes;

}
