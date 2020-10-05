package yongs.temp.filter;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.Jwts;

public class JwtPreFilter extends ZuulFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtPreFilter.class);
    
    private static final String ACCESS_TOKEN = "access-token";
    private static final String excludeURI = "/any/";
    private static final String imagePath = "/displayImg";
	private final String secretKey = "ThisIsMySecretKey";	
	   
	@Override
	public boolean shouldFilter() {
		return true;
	}
	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 1;
	}
	
	@Override
	public Object run() throws ZuulException {
	    RequestContext ctx = RequestContext.getCurrentContext();       
        HttpServletRequest req = ctx.getRequest();
        String authorizationToken = null;
        
        if(!req.getRequestURI().startsWith(excludeURI)) {
        	// 이미지 display인 경우 header가 아닌 query로 token을 체크 
        	if(req.getRequestURI().contains(imagePath)) {
            	authorizationToken = (String) req.getParameter(ACCESS_TOKEN);
                logger.debug(">>> access-token: |" + authorizationToken + "|");  
        	
            // 기본적으로 header에 있는 token을 체크
        	} else {
        		authorizationToken = req.getHeader(ACCESS_TOKEN);
        		logger.debug(">>> access-token: |" + authorizationToken + "|");
        	}
        	
            if (!validateToken(authorizationToken)) {
            	onError(ctx, HttpStatus.UNAUTHORIZED);
            	logger.debug(">>> access-token: |" + authorizationToken + "|");            
            }
        }

        return null;
	}
	
    private boolean validateToken(String jwt) {
    	if(jwt != null) {
    		try{
    			Jwts.parser().setSigningKey(this.generateKey()).parseClaimsJws(jwt);
    			return true;            
            } catch (Exception e) {
            	return false;
            }   		
    	} else {
    		return false;
    	} 
    }
 
    private String generateKey(){
    	return Base64.getEncoder().encodeToString(this.secretKey.getBytes());
    }
    
	private void onError(RequestContext ctx, HttpStatus httpStatus)  {
    	// Zuul 진행은 false
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(httpStatus.value());
    }
}
