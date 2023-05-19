# SpringBoot Web Mvc Default 
의존성에 springboot-web만 추가하고 아무것도 설정하지 않은 상태에서의 테스트한 결과를 기록한다. @EnableWebMvc 적용하지 않았다. 


## dependency 
```xml
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.7.4</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.jirepos</groupId>
	<artifactId>autoconfig</artifactId>
	<version>1.0.0</version>
	<name>autoconfig</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>17</java.version>
	</properties>

	<dependencies>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>

	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>
```


## Application
@SpringBootApplication만 적용했다. 

```java
package com.jirepos;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AutoconfigApplication {
	public static void main(String[] args) {
		SpringApplication.run(AutoconfigApplication.class, args);
	}

}

```



## 정적파일 리소스 
public과 static에 각각 파일을 하나 생성했다. 

```
📁root
 📁resources
   📁public
     📄test.html
   📁static 
     📄index.html
```   
URL만 입력 시 index.html이 반환된다. 
```
http://localhost/
```
test.html을 다음과 같이 요청했다. 
```
/test.html
```

스프링 부트의 기본 정적 리소스 위치는 다음과 같다. 이는 ResourceProperties에 정의되어 있으며, 스프링 부트 1.5.3.RELEASE 부터 현재 기준 가장 최신 버전인 2.3.3.RELEASE 까지 동일하다.
* classpath:/META-INF/resources/
* classpath:/resources/
* classpath:/static/
* classpath:/public/

src/main/resources 아래에 META-INF/resources를 만들고 meta.html을 생성한다. 

```
📁root
 📁resources
   📁META-INF
     📁resources
       📄meta.html
   📁public
     📄test.html
   📁static 
     📄index.html
```   

브라우저에서 다음과 같이 호출한다. 
```
/meta.html
```
정성적으로 호출이된다. 

## 프러퍼티 적용
static-path-pattern을 다음과 같이 적용한다. 

```yaml
spring:
  mvc:
    static-path-pattern: /**   
```
위에서와 동일하게 호출이 된댜. 

이제 /res로 경로를 바꾸어 본다. 
```yaml
spring:
  mvc:
    static-path-pattern: /res/**
```

index.html은 변함없이 호출된다. 
```
http://localhost
```
meta.html과 test.html은 다음과 같이 호출한다. 
```
/res/meta.html
/res/test.html
```
정상적으로 호출이된다. 

static-locations를 적용해 보자. 
```yaml
spring:
  mvc:
    static-path-pattern: /res/**   
  web:
    resources:
      static-locations: classpath:/static/  
      #add-mappings: false
```

index.html이 정상적으로 호출이 되지 않는다.  다음 둘 다 정상출력이 되지 않는다. 
```
http://localhost/ 
http://localhost/index.html
```

다음과 같이 해야 출력이된다. 
```
/res/index.html
```
public도 경로에 포함을 한다. 
```yaml
spring:
  mvc:
    static-path-pattern: /res/**   
  web:
    resources:
      static-locations: classpath:/static/ , classpath:/public/
      #add-mappings: false
```
다음 둘 다 호출이 가능하다. 
```
/res/index.html
/res/test.html
```
그러나 static-locations 설정과 관계없이 /META-INF/resources 아래에 있는 meta.html은 호출이 가능했다. 


다음과 같이 배열로 선언해도 콤마와 같이 정상 인식한다. 
```
spring:
  mvc:
    static-path-pattern: /res/**   
  web:
    resources:
      static-locations: 
        - classpath:/static/ 
        - classpath:/public/ 
      #add-mappings: false

```



## Freemarker 적용 
pom.xml파일에 의존성을 추가한다. 

```xml
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-freemarker</artifactId>
		</dependency>
```

application.yml에 다음을 추가한다. 
```yaml
spring:
  freemarker:
    suffix: .ftl
    template-loader-path: classpath:/templates
```
컨트롤러를 생성한다. 
```java

package com.jirepos.autoconfig.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/fm")
public class FreemarkerController {
    
    @RequestMapping("/index")
    public String index() {
        return "/free";
    }
}
```

templates 폴더 아래에 free.ftl 파일을 만든다. 
다음과 같이 호출하면 잘 동작한다.
```
/fm/index
```

## JSP 적용 

pom.xml에 다음을 추가한다.  packaging은 war로 변경한다. 
```xml
<groupId>com.jirepos</groupId>
<artifactId>autoconfig</artifactId>
<packaging>war</packaging>

<!-- war로 패키징 하는 경우 컴파일 시에 제공하고, 런타임 시에는 제공하지 않는다. -->
<!-- 내장 톰캣 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-tomcat</artifactId>
    <scope>provided</scope>
</dependency>


<!-- SpringBoot에서 JSP 사용설정  -->
<dependency>
    <groupId>org.apache.tomcat.embed</groupId>
    <artifactId>tomcat-embed-jasper</artifactId>
   <scope>provided</scope>
</dependency>
```        

application.yml에 다음을 추가한다. 
```yaml
spring:
  freemarker:
    suffix: .ftl
    template-loader-path: classpath:/templates
  mvc:
    view:
      prefix: /WEB-INF/views/
      suffix: .jsp
    static-path-pattern: /res/**  
```    


webapp 폴더를 만들고 다음과 같이 구성한다. 
```
📁root
 📁resources
   📁META-INF
     📁resources
       📄meta.html
   📁public
     📄test.html
   📁static 
     📄index.html
 📁webapp 
   📁WEB-INF
     📁views
       📄index.jsp
   📁resources 
      📄main.js
```   

webapp/WEB-INF/views 아래의 jsp를 다음과 같이 호출한다. 
```
/jsp/index
```
정상적으로 호출이 된다. 


weapp/resources 아래의 main.js을 다음과 같이 호출한다. 
```
/resources/main.js
```
정상적으로 호출이 되지 않는다. 

이것은 Spring이 처리하지 않기 때문인 것으로 판단된다. 

application.yaml에 댜음을 추가한다. 
```yaml
server:
  servlet:
    # 모든 Servlet Container 에는 default Servlet 이라는게 등록되어 있다.
    # 실제로 tomcat 을 설치한 다음 conf 디렉토리 하위의 web.xml 을 열어보면 default Servlet 이 등록되어 있는것을 확인할 수 있다.
    register-default-servlet: true  
```
WebMvcConfigurer를 구현한 클래스를 다음과 같이 정의한다. 
```java
package com.jirepos.autoconfig.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class DispatcherConfig implements WebMvcConfigurer {
    public void configureDefaultServletHandling(
        org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer configurer) {
      configurer.enable();
    }
    
}
```

이제 정상적으로 호출이 된다.  freemarker, jsp 와 리소스 모두 정상적으로 호출이 된다. 


## Mustache 적용 

pom.xml 파일에 의존성을 추가한다. 
```xml
<!-- mustache -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mustache</artifactId>
</dependency>
```        
application.yml에 다음을 추가한다. 
```yaml
spring:
  mustache:
    prefix: classpath:/templates/mustache/
    suffix: 
```
Mustache 파일을 /templates/mustache 아래에 만든다. 
```
📁root
 📁resources
   📁templates
     📁mustache
       📄start.mustache
```   


Mustache View를 호출할 Controller을 작성한다. 
```java
package com.jirepos.autoconfig.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/mustache")
public class MustacheController {

    @GetMapping("/index")
    public String index() {
        return "start.mustache";
    }

}
````

## 결론
@SpringBootApplication 어노테이션만 적용해도 appliaion.yml에 설정만으로도  jsp, freemarker, mustache와 static 경로등을 설정할 수 있었다. 

Spring에서 SpringBoot라는 프레임워크를 내놓기 시작하면서 SpringBoot의 AutoConfigure(자동 구성) 기능을 통해 많은 설정들이 자동화되기 시작하였다.

SpringBoot 애플리케이션을 생성하면 main 클래스에 @SpringBootApplication 어노테이션이 자동으로 붙어있는데, 이 어노테이션은 내부에 @EnableAutoConfiguration이라는 어노테이션을 갖고 있다.


```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@SpringBootConfiguration
@EnableAutoConfiguration
@ComponentScan(excludeFilters = { @Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),
		@Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class) })
public @interface SpringBootApplication {
    ...

}

```

@EnableAutoConfiguration은 내부적으로 @EnableWebMvc과 동일한 기능을 사용하기 때문에 우리는 메세지 컨버터(Message Converter)나 뷰 리졸버(View Resolver) 또는 인터셉터(Interceptor) 등을 따로 설정해주지 않아도 되고, 추가로 @EnableWebMvc 기반의 설정도 추가하지 않아도 된다.
즉, SpringBoot 프로젝트를 생성만 하면 이러한 부분을 자동으로 이용할 수 있게 된 것이다.


















