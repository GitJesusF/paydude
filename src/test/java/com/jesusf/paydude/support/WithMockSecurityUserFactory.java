package com.jesusf.paydude.support;

import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.security.SecurityUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.List;

public class WithMockSecurityUserFactory implements WithSecurityContextFactory<WithMockSecurityUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockSecurityUser annotation) {
    SecurityUser user = new SecurityUser(
        annotation.id(),
        annotation.email(),
        "password",
        UserStatus.ACTIVE,
        null,   // no account expiry for test users
        null,   // no credentials expiry for test users
        false,  // no second factor for test users (JWT-rebuilt principals carry false anyway)
        List.of(new SimpleGrantedAuthority(annotation.role()))
    );

    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(auth);
    return context;
  }
}