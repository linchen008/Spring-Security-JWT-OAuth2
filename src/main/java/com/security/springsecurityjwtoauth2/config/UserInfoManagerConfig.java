package com.security.springsecurityjwtoauth2.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.security.springsecurityjwtoauth2.repo.UserInfoRepo;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 09/07/2024 16:22
 * @Description :
 */
@Service
@RequiredArgsConstructor
public class UserInfoManagerConfig implements UserDetailsService {

    private final UserInfoRepo userInfoRepo;

    /**
     * Locates the user based on the username. In the actual implementation, the search
     * may possibly be case sensitive, or case insensitive depending on how the
     * implementation instance is configured. In this case, the <code>UserDetails</code>
     * object that comes back may have a username that is of a different case than what
     * was actually requested..
     *
     * @param emailId the username identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     *                                   GrantedAuthority
     */
    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        return userInfoRepo
                .findByEmailId(emailId)
                .map(UserInfoConfig::new)
                .orElseThrow(()->new UsernameNotFoundException("UserEmail: "+ emailId+"does not exist"));
    }
}
