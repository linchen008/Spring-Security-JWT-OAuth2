package com.security.springsecurityjwtoauth2.config.user;

import com.security.springsecurityjwtoauth2.entity.UserInfoEntity;
import com.security.springsecurityjwtoauth2.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 09/07/2024 22:58
 * @Description : - Initialization Tasks: Execute code that needs to run after the Spring application context is created.
 *                  Data Seeding: Populate initial data into the database.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class InitialUserInfo implements CommandLineRunner {
    private final UserInfoRepo userInfoRepo;
    private final PasswordEncoder passwordEncoder;
    /**
     * Callback used to run the bean.
     *
     * @param args incoming main method arguments
     * @throws Exception on error
     */
    @Override
    public void run(String... args) throws Exception {
        UserInfoEntity manager = new UserInfoEntity();
        manager.setUserName("manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setEmailId("manager@email.com");
        manager.setRoles("ROLE_MANAGER");

        UserInfoEntity admin = new UserInfoEntity();
        admin.setUserName("admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setEmailId("admin@email.com");
        admin.setRoles("ROLE_ADMIN");

        UserInfoEntity user = new UserInfoEntity();
        user.setUserName("user");
        user.setPassword(passwordEncoder.encode("password"));
        user.setEmailId("user@email.com");
        user.setRoles("ROLE_USER");

        userInfoRepo.saveAll(List.of(manager, admin, user));
    }
}
