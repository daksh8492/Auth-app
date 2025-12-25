package com.auth.security;

import com.auth.entities.Provider;
import com.auth.entities.RefreshToken;
import com.auth.entities.User;
import com.auth.repositories.RefreshTokenRepository;
import com.auth.repositories.UserRepo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            logger.info("OAUTH2 LOGIN SUCCESSFUL");
            logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

            String registrationId = "unknown";
            if (authentication instanceof OAuth2AuthenticationToken token){
                registrationId = token.getAuthorizedClientRegistrationId();
            }

            logger.info("registrationId: {}",registrationId);
            logger.info("oAuth2User: {}",oAuth2User);

            User user;
            switch (registrationId){
                case "google" -> {
                    String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                    String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                    String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                    String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
                    User newUser = User.builder()
                            .name(name)
                            .image(picture)
                            .email(email)
                            .enable(true)
                            .provider(Provider.GOOGLE)
                            .build();
                    logger.info("Saving new User: {}", newUser);
                    user = userRepo.findByEmail(email).orElseGet(()-> userRepo.save(newUser));

                    String jti = UUID.randomUUID().toString();
                    RefreshToken refreshTokenOb = RefreshToken.builder()
                            .user(user)
                            .jti(jti)
                            .createdAt(Instant.now())
                            .revoked(false)
                            .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTTLSeconds()))
                            .build();

                    refreshTokenRepository.save(refreshTokenOb);

                    String accessToken = jwtService.generateAccessToken(user);
                    String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());
                    cookieService.attachRefreshCookie(response, refreshToken, jwtService.getRefreshTTLSeconds().intValue());

                }
            }

            response.sendRedirect("http://localhost:5173/auth/success");
    }
}
