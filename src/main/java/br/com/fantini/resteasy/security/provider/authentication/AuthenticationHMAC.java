package br.com.fantini.resteasy.security.provider.authentication;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.map.util.ISO8601Utils;

import br.com.fantini.resteasy.security.utils.HttpRequestHMAC;
import br.com.fantini.resteasy.security.utils.UtilsHMAC;

/**
 * Classe responsavel pelo processo de validacao da autenticacao do client.
 * @author fantini
 */
public class AuthenticationHMAC {
	
	/**
	 * Valida os dados enviados pelo client para
	 * realizar sua autenticacao. Foi padronizado
	 * 15 minutos para expiracao da requisicao.
	 * @author fantini
	 * @since 12/03/2013
	 * @param method
	 * @param contentType
	 * @param contentMd5
	 * @param uri
	 * @param date
	 * @param accessKey
	 * @param secretKey
	 * @param signature
	 * @param parameters
	 * @return Boolean
	 * @throws Exception
	 */
	public static Boolean verify(String method, String contentType, String contentMd5, String uri, String date, String accessKey, String secretKey, String signature, String version, Map<String,List<String>> parameters) throws Exception {
		
		Date contentDate = ISO8601Utils.parse(date);
		Date currentDate = new Date();
		String _version = UtilsHMAC.VERSION.split("\\.")[0];
		
		long diffMinutes = (currentDate.getTime() - contentDate.getTime()) / 60000;
		
		if (Math.abs(diffMinutes) <= 15 && _version.equals(version.split("\\.")[0]))
			return signature.equals(UtilsHMAC.generateRestSignature(new HttpRequestHMAC(method, contentType, uri, accessKey, secretKey, date, version, parameters)));
		
		return false;
	}
}
