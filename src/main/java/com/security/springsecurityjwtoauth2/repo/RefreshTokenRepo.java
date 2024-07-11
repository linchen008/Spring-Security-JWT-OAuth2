package com.security.springsecurityjwtoauth2.repo;

import com.security.springsecurityjwtoauth2.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 08/07/2024 23:47
 * @Description :
 */
@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity,Long> {
    Optional<RefreshTokenEntity> findByRefreshToken(String refreshToken);

//    //using username to query all place can be revoked token
//    @Query(value = "select rt.* from REFRESH_TOKEN rt " +
//            "inner join USER_DETAILS ud " +
//            "on rt.user_id = ud.id " +
//            "where ud.email = :userEmail " +
//            "and rt.revoked = false",nativeQuery = true)
//    List<RefreshTokenEntity> findAllRefreshTokenByUserEmailId(String userEmail);
}
