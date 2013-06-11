package security.provider.interceptor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PostProcessInterceptor;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;

import security.provider.annotation.RestLog;
import security.provider.annotation.RestRolesAllowed;
import security.provider.authentication.AuthenticationHMAC;
import security.provider.dto.LogWSDTO;
import security.provider.jdbc.JDBCSecurity;
import security.utils.HttpHeadersHMAC;
import security.utils.TypeLog;
import security.utils.UtilsHMAC;

/**
 * Classe responsavel por interceptar a requisicao rest. Valida a seguranca
 * dos metodos e classes anotados. Efetua o processo de log conforme configuracao.
 * @author fantini
 */
@Provider
@ServerInterceptor
public class SecurityInterceptor implements PreProcessInterceptor, PostProcessInterceptor {

	@Context
	HttpServletRequest request;
	
	public ServerResponse preProcess(HttpRequest arg0, ResourceMethod arg1) throws Failure, WebApplicationException {
		ServerResponse response = null;
		JDBCSecurity jdbcSecurity = new JDBCSecurity();
		Set<TypeLog> typeLog = new HashSet<TypeLog>();
		try {
			
			Boolean transaction = false;
			
			if (arg1.getResourceClass().isAnnotationPresent(RestLog.class)) {
				transaction = arg1.getResourceClass().getAnnotation(RestLog.class).transaction();
				typeLog.addAll(Arrays.asList(((RestLog)arg1.getResourceClass().getAnnotation(RestLog.class)).value()));
			}
			
			if (arg1.getMethod().isAnnotationPresent(RestLog.class)) {
				transaction = arg1.getMethod().getAnnotation(RestLog.class).transaction();
				typeLog.addAll(Arrays.asList(((RestLog)arg1.getMethod().getAnnotation(RestLog.class)).value()));				
			}
						
			if (transaction) {
				request.setAttribute(HttpHeadersHMAC.TRANSACTION.getValue(), jdbcSecurity.getTransacao());
			}
				
			if(typeLog.contains(TypeLog.BEFORE) || typeLog.contains(TypeLog.ALL)) {
				jdbcSecurity.logWs(new LogWSDTO(TypeLog.BEFORE, request));
			}
		
			if (arg1.getResourceClass().isAnnotationPresent(RestRolesAllowed.class) || arg1.getMethod().isAnnotationPresent(RestRolesAllowed.class)) {
				if (UtilsHMAC.isBlank(request.getHeader(HttpHeadersHMAC.AUTHORIZATION.getValue()))){
					response = (ServerResponse)Response.status(Response.Status.UNAUTHORIZED).entity(new Exception("Permissão negada")).type(MediaType.APPLICATION_JSON).build();
					if(typeLog.contains(TypeLog.ERROR) || typeLog.contains(TypeLog.ALL)) {
						jdbcSecurity.logWs(new LogWSDTO(TypeLog.UNAUTHORIZED, request));
					}
				}
				
				String[] key = request.getHeader(HttpHeadersHMAC.AUTHORIZATION.getValue()).split(":");
				String accessKey = key[0];
				String signature = key[1];
				List<String> roles = new ArrayList<String>();
				
				if (arg1.getResourceClass().isAnnotationPresent(RestRolesAllowed.class)) {
					roles.addAll(Arrays.asList(arg1.getResourceClass().getAnnotation(RestRolesAllowed.class).value()));
				}
				 
				if(arg1.getMethod().isAnnotationPresent(RestRolesAllowed.class)) {
					roles.addAll(Arrays.asList(arg1.getMethod().getAnnotation(RestRolesAllowed.class).value()));
				}
				
				if (!Collections.disjoint(jdbcSecurity.getRoles(accessKey),roles)) {				
					Map<String,List<String>> parameters = new HashMap<String, List<String>>();
					for(Entry<String,List<String>> item: (Set<Entry<String,List<String>>>)arg0.getDecodedFormParameters().entrySet()) {
						parameters.put(item.getKey(), item.getValue());
					}
					for(Entry<String,List<String>> item: (Set<Entry<String,List<String>>>)arg0.getUri().getQueryParameters().entrySet()) {
						parameters.put(item.getKey(), item.getValue());
					}
					
					if (!AuthenticationHMAC.verify(
							request.getMethod(),
							request.getContentType(),
							request.getHeader(HttpHeadersHMAC.CONTENTMD5.getValue()), 
							request.getRequestURI(), 
							request.getHeader(HttpHeadersHMAC.DATE.getValue()), 
							accessKey, jdbcSecurity.getSecretKey(accessKey), 
							signature, request.getHeader(HttpHeadersHMAC.VERSION.getValue()), parameters)) {
						response = (ServerResponse)Response.status(Response.Status.UNAUTHORIZED).entity(new Exception("Permissão negada")).type(MediaType.APPLICATION_JSON).build();
						if(typeLog.contains(TypeLog.UNAUTHORIZED) || typeLog.contains(TypeLog.ALL)) {
							jdbcSecurity.logWs(new LogWSDTO(TypeLog.UNAUTHORIZED, request));
						}
					}
				} else {
					response = (ServerResponse)Response.status(Response.Status.UNAUTHORIZED).entity(new Exception("Permissão negada")).type(MediaType.APPLICATION_JSON).build();
					if(typeLog.contains(TypeLog.UNAUTHORIZED) || typeLog.contains(TypeLog.ALL)) {
						jdbcSecurity.logWs(new LogWSDTO(TypeLog.UNAUTHORIZED, request));
					}
				}
			}
		} catch(Exception e) {
			response = (ServerResponse) Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e).type(MediaType.APPLICATION_JSON).build();
			if(typeLog.contains(TypeLog.ERROR) || typeLog.contains(TypeLog.ALL)) {
				jdbcSecurity.logWs(new LogWSDTO(TypeLog.ERROR, request));
			}
		}
		return response;
	}

	public void postProcess(ServerResponse response) {
		
		Set<TypeLog> typeLog = new HashSet<TypeLog>();
		
		if(response.getResourceMethod().isAnnotationPresent(RestLog.class)){
			
			typeLog.addAll(Arrays.asList(((RestLog)response.getResourceMethod().getAnnotation(RestLog.class)).value()));
			
			if (typeLog.contains(TypeLog.AFTER) || typeLog.contains(TypeLog.ALL)) {
				new JDBCSecurity().logWs(new LogWSDTO(TypeLog.AFTER, request));
			}
		}
	}
}