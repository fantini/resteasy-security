package security.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Classe auxiliar utilizada para compor todos os
 * parametros para realizar a requisicao REST.
 * @author fantini
 */
public class HttpRequestHMAC {
	
	private final String method;
	private final String contentType;
	private final String uri;
	private final String date;
	private final String content;
	private String authorization;
	private final String contentMd5;
	private final String accessKey;
	private final String secretKey;
	private final String version;
	private Map<String,String> headers;
	
	public HttpRequestHMAC(String method, String contentType, String uri, 
			String accessKey, String secretKey, String date, String version, Map<String,List<String>> parameters) {
		this.method = method;
		this.contentType = contentType;
		this.uri = uri;
		this.accessKey = accessKey;
		this.date = date;
		this.content = UtilsHMAC.formatContentForm(parameters);
		this.secretKey = secretKey;
		this.contentMd5 = UtilsHMAC.generateMd5(this.content);
		this.version = version;
	}
	
	public String getMethod() {
		return method;
	}
	public String getContentType() {
		return contentType;
	}
	public String getUri() {
		return uri;
	}
	public String getAccessKey() {
		return accessKey;
	}
	protected String getSecretKey() {
		return secretKey;
	}
	public String getDate() {
		return date;
	}
	public String getContent() {
		return content;
	}
	public String getAuthorization() {
		if (authorization == null)
			authorization = UtilsHMAC.generateRestSignature(this);
		return authorization;
	}
	public String getContentMd5() {
		return contentMd5;
	}
	public Map<String,String> getHeaders() {
		
		if (this.headers != null)
			return this.headers;
		
		Map<String,String> headers = new HashMap<String, String>();
		
		headers.put(HttpHeadersHMAC.DATE.getValue(), this.date);
		
		if (!UtilsHMAC.isBlank(this.contentType))
			headers.put(HttpHeadersHMAC.CONTENTTYPE.getValue(), this.contentType);
		if (!UtilsHMAC.isBlank(this.contentMd5))
			headers.put(HttpHeadersHMAC.CONTENTMD5.getValue(), this.contentMd5);
		if (!UtilsHMAC.isBlank(this.version))
			headers.put(HttpHeadersHMAC.VERSION.getValue(), this.version);
		
		headers.put(HttpHeadersHMAC.AUTHORIZATION.getValue(), accessKey+":"+this.getAuthorization());
		
		this.headers = headers;
		
		return this.headers;
	}

	public String getVersion() {
		return version;
	}
}
