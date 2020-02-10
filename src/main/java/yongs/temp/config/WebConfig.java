package yongs.temp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import yongs.temp.filter.JwtPreFilter;

@Configuration
public class WebConfig implements WebMvcConfigurer {	

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
				.allowedOrigins("*")
				.allowCredentials(true)	
				.allowedHeaders("*")
				.allowedMethods(
						HttpMethod.GET.name(),
				        HttpMethod.HEAD.name(),
				        HttpMethod.POST.name(),
				        HttpMethod.PUT.name(),
				        HttpMethod.DELETE.name());
    }

    @Bean
    public JwtPreFilter jwtPreFilter() {
        return new JwtPreFilter();
    }
}
