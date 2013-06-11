package security.utils;

/**
 * Enum contendo os parametros utilizados para
 * realizar autenticacao
 * @author fantini
 */
public enum HttpHeadersHMAC {
	AUTHORIZATION 	("Authorization"),
	CONTENTTYPE 	("Content-Type"),
	CONTENTMD5		("Content-Md5"),
	DATE			("Date"),
	TRANSACTION		("Content-Transaction"),
	VERSION			("Version");
	
	private final String value;
	
	private HttpHeadersHMAC(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}
}
