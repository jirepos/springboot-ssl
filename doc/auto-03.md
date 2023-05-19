# WebMvcConfigurer 사용 


 WebMvcConfigurer를 사용하면 @EnableWebMvc가 자동적으로 세팅해주는 설정에 개발자가 원하는 설정을 추가할 수 있게 된다. 즉 Override가 가능하다.



## 리소스 추가 설정 

addResourceHandlers()을 오버라이드 한 경우에는 /public, /static 경로로 접근할 수 있다. 

```java
package com.jirepos.autoconfig.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class DispatcherConfig implements WebMvcConfigurer {
  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    // url을 지정하여 실제 리소스 경로를 설정 
    // registry.addResourceHandler("/public/**").addResourceLocations("classpath:/public/", "classpath:/static/");// .setCachePeriod(0);
    registry.addResourceHandler("/public/**").addResourceLocations("classpath:/public/");// .setCachePeriod(0);
    registry.addResourceHandler("/static/**").addResourceLocations("classpath:/static/");// .setCachePeriod(0);
  }

}

```
다음과 같이 호출한다 
```
/public/test.html
/static/index.html
```
정상적으로 호출된다. 


application.yml에 다음과 같이 설정이 되어 있다.  
```
spring:
    view:
      suffix: .jsp
    static-path-pattern: /res/**   
  web:
    resources:
      static-locations: 
        - classpath:/static/ 
        - classpath:/public/ 
```

다음과 같이 역시 호출이 가능하다. 
```
/res/test.html
/res/index.html
```
>  applicaion.yml 설정을 주석처리하고 addResourceHandlers()를 사용하는 것이 좋을 것 같다. 



## 프리마커 설정
applicaion.yml의 다음 설정을 주석처리한다. 

```yaml
spring:
  # mustache:
  #   prefix: classpath:/templates/mustache/
  #   suffix: 
```  
FreeMarkerViewResolver 빈을 생성한다. 

```java
  @Bean 
  public FreeMarkerViewResolver freemarkerViewResolver() { 
      FreeMarkerViewResolver resolver = new FreeMarkerViewResolver(); 
      resolver.setCache(true); 
      resolver.setPrefix("classpath:/templates/mustache"); // 뷰의 위치
      resolver.setSuffix(""); 
      return resolver; 
  }
```
다음과 같이 호출한다. 
```
/fm/index
```
정상적으로 호출이 된다. 


## Mustache 설정

MustacheViewResolver 빈을 생성한다. 
```java
  @Bean 
  public MustacheViewResolver mustacheViewResolver() { 
    MustacheViewResolver resolver = new MustacheViewResolver();
    resolver.setCharset("utf-8");
		resolver.setContentType("text/html;charset=utf-8");
		resolver.setPrefix("classpath:/templates/"); // 뷰의 위치
		resolver.setSuffix(".html");
      return resolver; 
  }
  ```

  ## JSP 설정
  InternalResourceView 빈을 생성한다. 
  ```java
    @Bean
  public ViewResolver viewResolver() {
    InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
    // viewResolver.setPrefix("/WEB-INF/");
    // viewResolver.setSuffix(".jsp");
    return viewResolver;
  }
  ```


  ## Cors Filter 생성 
  ```java
    /**
   * CorsFilter Bean을 생성한다. 
   * GraphQL을 사용할 경우에는 Filter를 적용해야 한다. Profile이 local인 경우에만 적용한다.
   */
  @Bean
  @Profile("local")
  public CorsFilter corsFilter() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    final CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("http://localhost:8080");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    source.registerCorsConfiguration("/graphql/**", config);
    return new CorsFilter(source);
  }// :
```

## Cors 설정
Cors 설정을위해 addCorsMappings()을 오버라이드 한다. 
```java
  /**
   * Cors설정을 처리한다. 
   */
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    // 사용자 정의 헤더를 다른 사이트에서 호출 시 노출하려면 exposedHeaders()를 사용해야 함
    registry.addMapping("/**")
        // https://stackoverflow.com/questions/46288437/set-cookies-for-cross-origin-requests
        // CORS 요청에서 cookies를 주고 받기 위해서
        .allowCredentials(true) // Access-Control-Allow-Credentials
        .allowedOriginPatterns("*")
        // .allowedOrigins("http://localhost")
        .exposedHeaders("X-Message", "X-Message-Code"); // .allowedHeaders("X-Message"); 이거 설정하면 헤더값 제어됨
  }// :
  ```

  ## 기타 
  메시지 컨버터 추가설정이나 인터셉터를 등록할 수 있다. 다른 글을 참조한다. 

  