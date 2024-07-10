package com.security.springsecurityjwtoauth2.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @Column(nullable = false,name = "USER_NAME")
    private String userName;

    @Column(nullable = false,name = "PASSWORD")
    private String password;

    @Column(nullable = false,name = "EMAIL_ID", unique = true)
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    private String roles;

//    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
//    private List<RefreshTokenEntity> refreshTokens;
}

