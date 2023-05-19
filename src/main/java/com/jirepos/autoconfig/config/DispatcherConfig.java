package com.jirepos.autoconfig.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.freemarker.FreeMarkerViewResolver;

@Configuration
public class DispatcherConfig implements WebMvcConfigurer {


    public void configureDefaultServletHandling(
        org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer configurer) {
      configurer.enable();
    }


  /**
   * src/main/resources/public, src/main/resources/static 정적 리소스 폴더를 사용할 수 있도록 설정한다. 
   */
  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    // url을 지정하여 실제 리소스 경로를 설정 
    // registry.addResourceHandler("/public/**").addResourceLocations("classpath:/public/", "classpath:/static/");// .setCachePeriod(0);
    registry.addResourceHandler("/public/**").addResourceLocations("classpath:/public/");// .setCachePeriod(0);
    registry.addResourceHandler("/static/**").addResourceLocations("classpath:/static/");// .setCachePeriod(0);
  }
  
  @Bean 
  public FreeMarkerViewResolver freemarkerViewResolver() { 
      FreeMarkerViewResolver resolver = new FreeMarkerViewResolver(); 
      resolver.setCache(true); 
      resolver.setPrefix("classpath:/templates/mustache"); // 뷰의 위치
      resolver.setSuffix(""); 
      return resolver; 
  }
  
}
