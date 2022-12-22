package com.golfzonaca.officesharingplatform.auth.token;

import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import java.util.Collection;

@EqualsAndHashCode(callSuper = false)
public class IdPwAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private final String id;
    private String pw;

    public IdPwAuthenticationToken(String id, String pw) {
        super(null);
        this.id = id;
        this.pw = pw;
        setAuthenticated(false);
    }

    public IdPwAuthenticationToken(String id, String pw, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.id = id;
        this.pw = pw;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.pw;
    }

    @Override
    public Object getPrincipal() {
        return this.id;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.pw = null;
    }
}
