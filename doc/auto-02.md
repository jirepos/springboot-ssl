# @EnableWebMvc Annotation 

Spring 기반의 프로젝트를 구축할 때 메시지 컨버터나 뷰 리졸버 등을 일일이 설정해야 했었다. 그래서 SpringBoot에서는 최신 전략들을 기반으로 설정을 자동화 하는 기능을 제공하기 시작했는데 그것이 @Enable~로 시작하는 어노테이션이다. 

@Enable로 시작하는 애노테이션을 @Configuration이 붙은 설정 클래스에 붙임으로써 이와 관련된 기능들을 편리하게 제공하고 있다. 그 중에서 @EnableWebMvc가 대표적인데, 이를 붙이면 스프링이 제공하는 웹과 관련된 최신 전략 빈들이 등록된다.



```java
@Configuration
@EnableWebMvc
public class DispatcherConfig { 

}
```

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


스프링 부트의 자동 구성에 대한 내용은 [Spring MVC Auto-configuration](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#web.servlet.spring-mvc.auto-configuration)에서 확인해 볼 수 있다. 



자동 구성은 다음의 특징들을 추가한다. 
* ContentNegotiatingViewResolver , BeanNameViewResolver 
* WebJars를 위한 지원을 포함하여, 정적 리소스 지원.  Support for serving static resources, including support for WebJars
* Converter, GenericConverter, and Formatter beans 자동 등록 
* HttpMessageConverters 지원 
* Automatic registration of MessageCodesResolver
* static index.html support.
* 



그런데, 스프링이 제공해주는 자동 설정들 외에 추가적인 설정이 필요할 수도 있다. 그래서 @Enable로 적용되는 인프라 빈에 대해 추가적인 설정을 할 수 있도록 ~Configurer로 끝나는 인터페이스를 제공하고 있다. 이를 구현한 클래스를 만들어 등록하면  @Enable 전용 어노테이션을 처리하는 단계에서 설정용 빈을 활용하여 인프라 빈의 설정을 마무리한다.  

@EnableMVC의 빈 설정자는 WebMvcConfigurer이며 이를 구현한 클래스를 만들고 @Configuration을 붙여 빈으로 등록하면 된다. 

그러나 주의할 것은 WebMvcConfigurer를 구현할 경우 @EnableWebMvc 어너테이션을 붙이지 말아야 한다. 

> If you want to keep those Spring Boot MVC customizations and make more MVC customizations (interceptors, formatters, view controllers, and other features), you can add your own @Configuration class of type WebMvcConfigurer but without @EnableWebMvc.


@EnableWebMvc를 통해 자동 설정되는 빈들의 설정자는 WebMvcConfigurer이며, 이를 구현한 클래스를 만들어야 한다. WebMvcConfigurer는 다음과 같은 구조를 가지고 있으며, 메소드의 이름은 대부분 add나 configure로 시작하는데, 각각은 다음의 의미를 갖고 있다.

WebMvcConfigurer는 다음과 같은 메서드들을 가지고 있는데, 대부분 add나  configurer로 시작한다. 

* add~: 기본 설정이 없는 빈들에 대하여 새로운 빈을 추가함
* configure~: 수정자를 통해 기존의 설정을 대신하여 등록함
* extend~: 기존의 설정을 이용하며 추가로 설정을 확장함


```java
public interface WebMvcConfigurer {

    // 몇가지만 나열함 
	default void configureAsyncSupport(AsyncSupportConfigurer configurer) {
	}

	default void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
	}

	default void addInterceptors(InterceptorRegistry registry) {
    }


	default void addResourceHandlers(ResourceHandlerRegistry registry) {
	}

	default void addCorsMappings(CorsRegistry registry) {
	}


	default void configureViewResolvers(ViewResolverRegistry registry) {
	}

```



. 기본적으로 스프링에서 제공해주는 웹 기능들에 추가적으로 커스터마이징을 하기를 원한다면 @EnableWebMvc없이 WebMvcConfigurer를 구현한 설정 파일만 등록해주어야 하며, 만약 WebMvcConfigurer를 구현하면서 @EnableWebMvc를 같이 붙여주면 스프링의 기본 설정들이 일부 무시된다.


스프링 MVC 자동구성은 WebMvcAutoConfiguration이 담당한다. 이 구성이 활성화되는 조건 중에 WebMvcConfigurationSupport 타입의 빈을 찾을 수 없을 때 라는 조건이 있다. @EnableWebMvc를 스프링 MVC 구성을 위한 클래스에 선언하면 WebMvcConfigurationSupport를 불러와 스프링 MVC를 구성한다. WebMvcConfigurationSupport가 컴포넌트로 등록되면 WebMvcAutoConfiguration은 비활성화 되기 때문이다.





