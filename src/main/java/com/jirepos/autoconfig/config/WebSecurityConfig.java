package com.jirepos.autoconfig.config;


import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.jirepos.core.util.ServletUtils;







/**
 * 스프링 버전이 업데이트 됨에 따라 WebSecurityConfigurerAdapter와 그 외 몇 가지들이 Deprecated 됐습니다
 * 기존에는 WebSecurityConfigurerAdapter를 상속받아 설정을 오버라이딩 하는 방식이었는데 바뀐 방식에서는 
 * 상속받아 오버라이딩하지 않고 모두 Bean으로 등록을 합니다. 
 * <br>
 * Deprecated 되어서 사용하지 않음
 * <pre>
 * import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
 * public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 * </pre>
 * 
 * @see https://velog.io/@pjh612/Deprecated%EB%90%9C-WebSecurityConfigurerAdapter-%EC%96%B4%EB%96%BB%EA%B2%8C-%EB%8C%80%EC%B2%98%ED%95%98%EC%A7%80
 * @see https://minkukjo.github.io/framework/2021/01/16/Spring-Security-04/  
 * @see https://bamdule.tistory.com/53
 */
@EnableWebSecurity // Spring Security를 활성화 시킵니다.
@Configuration
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class WebSecurityConfig {

 

    /** 
     * 패스워드를 암호화하기 위해서 사용한다. 
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        // BCrypt가 가장 많이쓰이는 해싱 방법
        // 패스워드 인크립트할 때 사용 
        return new BCryptPasswordEncoder();
    }


    /**
     * 권한 없음 처리.
     * 403 에러는 접근 권한 없는 url 요청 시 반환되는 응답코드입니다. 만약, 403에러 페이지가 아닌 다른 처리를 하고 싶다면 어떻게 해야할까요?
     * 이럴 때 이용하는 것이 바로 exceptionHandling 설정입니다.
     * 
     * HttpSecurity.exceptionHandling()을 해줘야 한다. 
     * @return
     */
    @Bean
	public AccessDeniedHandler accessDeniedHandler() {
        return ( request, response, e) -> {
            response.sendRedirect("/error/403");
            // response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			// response.setContentType("text/plain;charset=UTF-8");
			// response.getWriter().write("ACCESS DENIED");
			// response.getWriter().flush();
			// response.getWriter().close();
        };
    }



    /**
     * 인증 실패시 처리. filterChain()의 http.authorizeRequests()에서 인증정보가 없으면 여기서 처리한다.
     * @return
     */
	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
        // 로그인페이지 이동, 401오류 코드 전달
		return (request, response, e) -> {
			// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // // Content-Type은 http2.js에서 사용하므로 정확히 맞추어야 한다. 
			// response.setContentType("text/plain;charset=UTF-8");
			// response.getWriter().write("UNAUTHORIZED");
			// response.getWriter().flush();
			// response.getWriter().close();
            ServletUtils.responseUnauthorized(request, response);
		};
	}


 
    /** 
     * 공식 홈페이지를 보면, spring security 5.7이상에서 더 이상 WebSecurityConfigurerAdapter 사용을 권장하지 않는다고 한다.
     * SecurityFilterChain Bean 등록을 통해 해결한다.
     * ​SecurityFilterChain은 Filter 보다 먼저 실행됩니다.
     * SpringBoot에서 이미 default로 SecurityFilterChain을 등록하는 데, @Bean객체로 다시 주입하게 되면서 둘 중 하나만 선택하라는 오류가 나타나는 것이다.
     * @ConditionalOnDefaultWebSecurity
     * @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
     * 위 두 annotation을 class 위에 추가하고,
     * @Order(SecurityProperties.BASIC_AUTH_ORDER)
     * 위 annotation을 filter 함수 위에 추가하면 정상 작동이 된다.
     */
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //http.cors().disable()   // cors 방지 
        http.csrf().disable()   // csrf 방지 
            .logout().disable() // logout 방지 
            // .logout()  // 로그 아웃을 진행 
            //   .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))  // logout 경로 지정
            //   .logoutSuccessUrl("/")  // 로그아웃 성공 후 이동할 경로 지정
            //   .invalidateHttpSession(true)  // 세션을 삭제하는 것을 지정 (세션이 삭제되면 쿠키도 삭제된다) 
            .formLogin().disable() // form login 방지
            // .formLogin()   // form login 
            //    .loginPage("/login")   //커스텀 로그인 페이지 경로와 로그인 인증 경로를 등록합니다.
            //    .defaultSuccessUrl("/")   // 로그인 인증을 성공하면 이동하는 페이지를 등록합니다.
            //    .permitAll() 
            //.httpBasic().disable() // http basic 방지
            .httpBasic()  // http basic 사용. 사용자 인증방법으로는 HTTP Basic Authentication을 사용한다.
            .and() 
            //http 요청에 대해서 모든 사용자가 /** 경로로 요청할 수 있지만, /member/** , /admin/** 경로는 인증된 사용자만 요청이 가능합니다. 
            .authorizeRequests()  //HttpServletRequest 요청 URL에 따라 접근 권한을 설정합니다.
                .antMatchers("/public/**").permitAll() // permitAll은 모두에게 허용 
                .antMatchers("/demo/**").permitAll() // permitAll은 모두에게 허용 
                .antMatchers("/api/v1/auth/**").permitAll() // permitAll은 모두에게 허용 
                .antMatchers("/demo/board/**").authenticated()
                .antMatchers("/admin").authenticated(); // authenticated()는 인증된 사용자에게만 허용 
            //.and()

        // Headers에 대해서는 https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/headers.html 를 참조한다. 
        // Strict-Transport-Security is only added on HTTPS requests
        http.headers()
            //.frameOptions().disable() // frame 옵션 방지
            .httpStrictTransportSecurity().disable() // HttpStrictTransportSecurity 방지. HTTP Strict Transport Security (HSTS) will not be addded to the respons
            // .frameOptions().sameOrigin(); // frame 옵션 설정. 동일 도메인에서 iframe에 접근가능. 동일한 웹사이트에서 프레임을 사용할 수 있다.
            .frameOptions().disable(); 

        // 로그인 유지라는 체크박스에 체크를 하고 로그인을 하면 쿠키를 생성하고, 쿠키를 삭제하지 않으면 다음 로그인 시에도 쿠키를 사용하여 로그인 하도록 하는 것을 의미     
        http.rememberMe().disable();  // 로그인 유지 기능 disable 

        http.sessionManagement()
            .sessionFixation().changeSessionId() // 세션 유지를 위해 세션 아이디를 변경합니다. 인증에 성공할 때마다 새로운 세션을 생성하고, 새로운 JSESSIONID를 발급. 서블릿 3.1에서 기본값 
            // SessionCreationPolicy.ALWAYS 스프링 시큐리티가 항상 새로운 세션을 생성
            // SessionCreationPolicy.NEVER 스프링 시큐리티가 새로운 세션을 생성하지 않음
            // SessionCreationPolicy.IF_REQUIRED 스프링 시큐리티가 필요 시에 생성(기본값). 
            // SessionCreationPolicy.STATELESS 스프링 시큐리티가 새로운 세션을 생성하지 않음. 이 경우 세션을 사용하는 요청은 세션을 사용하지 않습니다.
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .maximumSessions(1)  // 같은 아이디로 1명만 로그인 할 수 있음
            .maxSessionsPreventsLogin(false); // 신규 로그인 사용자의 로그인이 허용되고, 기존 사용자는 세션아웃 됨. true 면 현재 사용자 인증 실패 
            //.expiredUrl(expiredUrl) // 세션이 만료되면 이동하는 페이지를 지정합니다.
            //.expiredSessionStrategy(securitySessionExpiredStrategy.setDefaultUrl("/caution/session_out.html")); 만료된 세션에 대한 전략 
            
        http.exceptionHandling()
             .authenticationEntryPoint(authenticationEntryPoint()) // 인증 실패시  401
             .accessDeniedHandler(accessDeniedHandler()); // 인가(권한) 실패시 accessDeniedHandler() 에서 처리하도록 한다. 403처리 
            
        return http.build(); 
    }//:

}/// ~
