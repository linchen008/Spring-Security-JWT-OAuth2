package com.security.springsecurityjwtoauth2.mapper;

import com.security.springsecurityjwtoauth2.dto.UserRegistrationDTO;
import com.security.springsecurityjwtoauth2.entity.UserInfoEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 12/07/2024 12:13
 * @Description :
 */
@Component
@RequiredArgsConstructor
public class UserInfoMapper {

    /*
        * This method converts the UserRegistrationDTO object to UserInfoEntity object.
     */
    public UserInfoEntity convertToEntity(UserRegistrationDTO userRegistrationDTO) {
        UserInfoEntity userInfoEntity = new UserInfoEntity();

        userInfoEntity.setEmailId(userRegistrationDTO.email());
        userInfoEntity.setUserName(userRegistrationDTO.username());
        userInfoEntity.setPassword(userRegistrationDTO.password());
        userInfoEntity.setMobileNumber(userRegistrationDTO.mobileNumber());
        userInfoEntity.setRoles(userRegistrationDTO.role());

        return userInfoEntity;
    }
}
