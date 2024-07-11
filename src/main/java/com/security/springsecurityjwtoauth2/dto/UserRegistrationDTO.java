package com.security.springsecurityjwtoauth2.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 11/07/2024 22:33
 * @Description :
 */

public record UserRegistrationDTO(
        @NotEmpty(message = "Username is required, must not be empty!")
        String username,

        String mobileNumber,

        @NotEmpty(message = "Email is required, must not be empty!")
        @Email(message = "Email should be valid")
        String email,

        @NotEmpty(message = "Password is required, must not be empty!")
        String password,

        @NotEmpty(message = "Role is required, must not be empty!")
        String role
) { }
