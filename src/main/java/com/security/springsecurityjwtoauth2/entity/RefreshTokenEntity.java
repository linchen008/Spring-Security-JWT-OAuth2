package com.security.springsecurityjwtoauth2.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 08/07/2024 23:34
 * @Description :
 */
@Data
@NoArgsConstructor
@AllArgsConstructor

/*
The @Builder annotation generates a builder class that
can be used to construct instances of the annotated class.
 */
@Builder

@Entity
@Table(name = "REFRESH_TOKENS")
public class RefreshTokenEntity {
    @Id
    @GeneratedValue
    private Long id;
    // Increase the length to a value that can accommodate your actual token lengths
    @Column(name = "REFRESH_TOKEN", nullable = false, length = 10000)
    private String refreshToken;

    @Column(name = "REVOKED")
    private boolean revoked;

    /**
     * Establishes a many-to-one relationship between {@link RefreshTokenEntity} and {@link UserInfoEntity}.
     * This annotation specifies that multiple {@code RefreshTokenEntity} instances can be associated with a single {@code UserInfoEntity}.
     * The {@code @JoinColumn} annotation indicates the column in the {@code REFRESH_TOKENS} table that is used to establish the foreign key relationship.
     *
     * @param user The {@link UserInfoEntity} that owns the refresh token. This is linked through the {@code user_id} column in the {@code REFRESH_TOKENS} table,
     * which references the {@code id} column of the {@code UserInfoEntity}.
     */
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private UserInfoEntity user;
}
