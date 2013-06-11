package security.provider.dto;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.codehaus.jackson.map.ObjectMapper;

import security.utils.HttpHeadersHMAC;
import security.utils.TypeLog;


public class LogWSDTO {

	private Integer level;

	private String user;
	private String signature;

	private String method;
	private String uri;
	private String date;
	private String ip;
	private String content;
	private String contentType;
	private Date dateLog;
	private String context;
	private Long transaction;

	public LogWSDTO(final TypeLog nivel, final HttpServletRequest request) {
		if (!request.getParameterMap().isEmpty()) {
			try {
				this.content = new ObjectMapper().writeValueAsString(request.getParameterMap());
			} catch(Exception e){}
		}
		this.level = nivel.ordinal();
		this.method = request.getMethod();
		this.contentType = request.getHeader(HttpHeadersHMAC.CONTENTTYPE.getValue());
		this.uri = request.getRequestURI();
		this.date = request.getHeader(HttpHeadersHMAC.DATE.getValue());
		if (request.getHeader(HttpHeadersHMAC.AUTHORIZATION.getValue()) != null && request.getHeader(HttpHeadersHMAC.AUTHORIZATION.getValue()).indexOf(":") != -1) {
			String[] key = request.getHeader(HttpHeadersHMAC.AUTHORIZATION.getValue()).split(":");
			this.user = key[0];
			this.signature = key[1];
		}
		this.ip = request.getRemoteHost();
		this.dateLog = new Date();
		this.context = request.getContextPath();
		this.transaction = (Long)request.getAttribute(HttpHeadersHMAC.TRANSACTION.getValue());
	}

	public Integer getLevel() {
		return level;
	}

	public String getUser() {
		return user;
	}

	public String getSignature() {
		return signature;
	}

	public String getMethod() {
		return method;
	}

	public String getUri() {
		return uri;
	}

	public String getDate() {
		return date;
	}

	public String getIp() {
		return ip;
	}

	public String getContent() {
		return content;
	}

	public String getContentType() {
		return contentType;
	}

	public Date getDateLog() {
		return dateLog;
	}
	
	public String getContext() {
		return context;
	}

	public Long getTransaction() {
		return transaction;
	}

}
