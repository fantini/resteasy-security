package br.com.fantini.resteasy.security.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.NameValuePair;

/**
 * Classe auxiliar.
 * @author fantini
 */
public class UtilsHMAC {
	
	private final static String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private final static String CHARSET = "UTF-8";
	public final static String VERSION = "1.1.1";
	
	/**
	 * Gera hash md5 da string passada como parametro e
	 * codifica para base64
	 * @author fantini
	 * @since 12/03/2013
	 * @param parameters
	 * @return String
	 */
	public static String generateMd5(String parameters) {
		try {
			return !isBlank(parameters) ? new String(Base64.encodeBase64(DigestUtils.md5(parameters.getBytes(CHARSET))), CHARSET) : null;
		} catch(Exception e) {
			return null;
		}
		
	}
	
	/**
	 * Gera assinatura utilizando o algoritmo HMAC conforme 
	 * o formato padronizado para os parametro da requisicao REST.
	 * @author fantini
	 * @since 12/03/2013
	 * @param httpRequest
	 * @return
	 */
	public static String generateRestSignature(HttpRequestHMAC httpRequest) {
		
		StringBuffer description = new StringBuffer();
		
		description.append(httpRequest.getMethod()).append("\n")
		.append(!isBlank(httpRequest.getContentMd5()) ? httpRequest.getContentMd5()+"\n" : "")
		.append(!isBlank(httpRequest.getContentType()) ? httpRequest.getContentType()+"\n" : "")
		.append(httpRequest.getDate()).append("\n")
		.append(httpRequest.getUri());
        
        return generateSignature(description.toString(), httpRequest.getSecretKey());
        
	}
	
	/**
	 * Gera assinatura utilizando o algoritmo HMAC.
	 * @author fantini
	 * @since 12/03/2013
	 * @param description
	 * @param secretKey
	 * @return String
	 */
	private static String generateSignature(String description, String secretKey) {
		
		try {
			// Create an HMAC signing object
	        Mac hmac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
	
	        // Use your Secret Key as the crypto secret key
	        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(CHARSET), HMAC_SHA1_ALGORITHM);
	        
	        hmac.init(secretKeySpec);
	
	        // Encode the signature bytes into a Base64 string
	        return new String(Base64.encodeBase64(hmac.doFinal(description.getBytes(CHARSET))), CHARSET);
	        
		} catch(Exception e) {}
		
		return null;
	}
	
	/**
	 * Formata os parametros da requisicao gerando
	 * uma string que segue o padrao de ordenacao definido.
	 * @author fantini
	 * @since 12/03/2013
	 * @param parameters
	 * @return String
	 */
	public static String formatContentForm(Map<String,List<String>> parameters) {
		
		if (parameters == null || parameters.isEmpty())
			return null;
		
		Map<String, List<String>> sortedParameters = new TreeMap<String, List<String>>(
            new Comparator<String>() {
                public int compare(String o1, String o2) {
                    return o1.toLowerCase().compareTo(o2.toLowerCase());
                }
            }
        );
		
		for (Entry<String,List<String>> entry: parameters.entrySet()) {
			if(entry.getValue().size() > 1) {
				Arrays.sort(entry.getValue().toArray(new String[]{}), 
					new Comparator<String>() {
						public int compare(String o1, String o2) {
							return o1.toLowerCase().compareTo(o2.toLowerCase());
						}
					}
				);
			}
		}
		
        sortedParameters.putAll(parameters);
        
        StringBuffer description = new StringBuffer();
        
        for (Map.Entry<String, List<String>> param : sortedParameters.entrySet()) {
        	description.append(param.getKey());
        	for(String item: param.getValue())
        		description.append(item);
        }
		
		return description.toString();
	}
	
	/**
	 * Converte os parametro da requisicao de List para Map.
	 * @author fantini
	 * @since 12/03/2013
	 * @param parameters
	 * @return Map
	 */
	public static Map<String,List<String>> convertListToMap (List<NameValuePair> parameters) {
		
		if (parameters == null)
			return null;
		
		Map<String,List<String>> _form = new HashMap<String, List<String>>();
		
		for(NameValuePair pair: parameters) {			
			if(!_form.containsKey(pair.getName()))
				_form.put(pair.getName(), new ArrayList<String>());

			_form.get(pair.getName()).add(pair.getValue());
		}
		
		return _form;
	}
	
	/**
	 * Verifica se a string é nula ou vazia.
	 * @author fantini
	 * @since 12/03/2013
	 * @param text
	 * @return Boolean
	 */
	public static Boolean isBlank(String text) {
		return text == null || text.trim().isEmpty();
	}
}
