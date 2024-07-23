package com.auth_system.authentication.system.auth.domain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserDetailService implements UserDetailsService {
    @Autowired
    private UserRepository userrepository;

    @Override
    public UserAuth loadUserByUsername(String username)  {
        UserAuth user = userrepository.findByUsername(username);
        if(user != null){
            return user;
        }
        return new UserAuth();
    }

}