package com.cattle.user.admin.controller;


import com.auth.common.core.util.R;
import com.cattle.user.admin.mapper.entity.RegisteredClientEntity;
import com.cattle.user.admin.service.RegisteredClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/registered_client")
public class RegisteredClientController {

    public final RegisteredClientService RegisteredClientService;

    @GetMapping("/client_id/{clientId}")
    public R<RegisteredClientEntity> findByClientId(@PathVariable("clientId") String clientId) throws Exception {
        return R.ok(RegisteredClientService.findByClientId(clientId));
    }

    @RequestMapping("/info")
    public String info(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object credentials = authentication.getCredentials();
        return  credentials.toString();
    }

}
