package com.security.springsecurityjwtoauth2.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 08/07/2024 23:23
 * @Description :
 */
@Data
@NoArgsConstructor
@AllArgsConstructor

@Entity
@Table(name = "USER_INFO")
public class UserInfoEntity {
    @Id
    @GeneratedValue()
    @Column(name = "ID")
    private Long id;

    @Column(nullable = false, name = "USER_NAME")
    private String userName;

    @Column(nullable = false, name = "PASSWORD")
    private String password;

    @Column(nullable = false, name = "EMAIL_ID", unique = true)
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    private String roles;

    /**
     * Represents the one-to-many relationship between a single {@link UserInfoEntity} and multiple {@link RefreshTokenEntity}.
     * This association indicates that each user can have multiple refresh tokens.
     * The 'mappedBy' attribute points to the 'user' field in the {@link RefreshTokenEntity} class, establishing the owning side of the relationship.
     * The 'cascade = CascadeType.ALL' configuration means that persistence operations (such as save and delete) on a {@link UserInfoEntity} instance
     * will be cascaded to the associated {@link RefreshTokenEntity} instances.
     * The 'fetch = FetchType.LAZY' indicates that the list of {@link RefreshTokenEntity} will be loaded on demand, which is a performance optimization.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<RefreshTokenEntity> refreshTokens;
}

