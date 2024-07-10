package com.security.springsecurityjwtoauth2.repo;

import com.security.springsecurityjwtoauth2.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 08/07/2024 23:46
 * @Description :
 */
@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity, Long> {
    Optional<UserInfoEntity> findByEmailId(String emailId);
}
