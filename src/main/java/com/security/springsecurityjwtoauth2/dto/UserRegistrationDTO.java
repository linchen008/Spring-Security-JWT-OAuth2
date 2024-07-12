package com.security.springsecurityjwtoauth2.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

/**
 * Data Transfer Object (DTO) for user registration.
 * This DTO encapsulates user registration data, ensuring that necessary validation
 * is performed before processing the user registration request.
 *
 * Fields include username, mobile number, email, password, and role, with specific
 * validation rules applied to ensure data integrity and compliance with requirements.
 */
public record UserRegistrationDTO<mobileNumber>(

        // Email must not be empty and should be in a valid format.
        @NotEmpty(message = "Email is required, must not be empty!")
        @Email(message = "Email should be valid")
        String email,

        // Username must not be empty; it is a required field for user registration.
        @NotEmpty(message = "Username is required, must not be empty!")
        String username,

        // Password must not be empty; it is a required field for securing the user account.
        @NotEmpty(message = "Password is required, must not be empty!")
        String password,

        // Role must not be empty; it is required to assign permissions and access control.
        @NotEmpty(message = "Role is required, must not be empty!")
        String role,

        // Mobile number is optional and does not have specific validation rules.
        String mobileNumber
) { }
