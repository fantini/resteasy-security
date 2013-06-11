package security.consumer.connection;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.codehaus.jackson.map.DeserializationConfig.Feature;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.util.ISO8601Utils;

import security.utils.HttpRequestHMAC;
import security.utils.UtilsHMAC;


/**
 * Classe utilizada pelo client Java para realizar a requisicao REST.
 * 
 * @author fantini
 */
public class HttpConnection {
	public static enum Method {
		GET, PUT, DELETE, POST
	};

	private final static String CHARSET = "UTF-8";
	private KeyStore clientKeyStore;
	private String accessKey;
	private String secretKey;
	private String passKeystore;
	private String locationKeystore;
	private static HttpConnection conn = null;

	private HttpConnection() {
	}

	public static synchronized HttpConnection getInstance(String accessKey,
			String secretKey) {

		return getInstance(accessKey, secretKey, null, null);
	}

	public static synchronized HttpConnection getInstance(String accessKey,
			String secretKey, String passKeystore, String locationKeystore) {

		if (conn == null) {
			conn = new HttpConnection();
		}

		conn.accessKey = accessKey;
		conn.secretKey = secretKey;
		conn.passKeystore = passKeystore;
		conn.locationKeystore = locationKeystore;
		if (!UtilsHMAC.isBlank(passKeystore)
				&& !UtilsHMAC.isBlank(locationKeystore)) {
			try {
				conn.clientKeyStore = KeyStore.getInstance("JKS");
				conn.clientKeyStore
						.load(new FileInputStream(conn.locationKeystore),
								conn.passKeystore.toCharArray());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return conn;
	}

	private HttpClient obterHttpClient(Boolean sslAuth, Integer port)
			throws Exception {

		HttpClient httpClient = null;

		if (sslAuth) {

			SSLSocketFactory socketFactory = new SSLSocketFactory(
					SSLSocketFactory.TLS,
					conn.clientKeyStore,
					conn.passKeystore,
					null,
					null,
					null,
					(X509HostnameVerifier) SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
			SchemeRegistry registry = new SchemeRegistry();
			registry.register(new Scheme("https", port, socketFactory));
			// ThreadSafeClientConnManager mgr = new
			// ThreadSafeClientConnManager(registry);
			PoolingClientConnectionManager pccm = new PoolingClientConnectionManager(
					registry);

			httpClient = (new DefaultHttpClient(pccm));
		} else {
			httpClient = new DefaultHttpClient();
		}

		return httpClient;
	}

	private String tratarRetorno(HttpResponse response) throws Exception {

		StringBuffer retorno = new StringBuffer();

		// Response possue conteudo
		if (response.getStatusLine().getStatusCode() != 204) {

			BufferedReader br = new BufferedReader(new InputStreamReader(
					response.getEntity().getContent(), "UTF-8"));

			String output;
			while ((output = br.readLine()) != null) {
				retorno.append(output);
			}

			// Gera uma Exception caso seja retornado um erro do provedor
			if (response.getStatusLine().getStatusCode() != 200) {
				throw new ObjectMapper().configure(
						Feature.FAIL_ON_UNKNOWN_PROPERTIES, false).readValue(
						retorno.toString(), Exception.class);
			}
		}

		return retorno.toString();
	}

	/**
	 * Executar requisicao.
	 * 
	 * @author fantini
	 * @since 25/02/2013
	 * @param url
	 * @param port
	 * @param sslAuth
	 * @param parameters
	 * @param method
	 * @return String
	 * @throws Exception
	 */
	private String executeRequest(String url, Integer port, Boolean sslAuth,
			List<NameValuePair> parameters, Method method) throws Exception {

		HttpRequestBase http = null;
		String contentType = "";

		List<NameValuePair> _parametros = URLEncodedUtils.parse(new URI(url),
				CHARSET);

		if (_parametros.isEmpty())
			_parametros = new ArrayList<NameValuePair>();

		if (parameters != null) {
			_parametros.addAll(parameters);
		} else {
			parameters = new ArrayList<NameValuePair>(0);
		}

		switch (method) {
		case GET:
			http = new HttpGet(url);
			break;
		case POST:
			http = new HttpPost(url);
			((HttpPost) http).setEntity(new UrlEncodedFormEntity(parameters,
					CHARSET));
			contentType = ((HttpPost) http).getEntity().getContentType()
					.getValue();
			break;
		case DELETE:
			http = new HttpDelete(url);
			break;
		case PUT:
			http = new HttpPut(url);
			((HttpPut) http).setEntity(new UrlEncodedFormEntity(parameters,
					CHARSET));
			contentType = ((HttpPut) http).getEntity().getContentType()
					.getValue();
		}

		HttpRequestHMAC request = new HttpRequestHMAC(http.getMethod(),
				contentType, http.getURI().getPath(), conn.accessKey,
				conn.secretKey, ISO8601Utils.format(new Date()),
				UtilsHMAC.VERSION, UtilsHMAC.convertListToMap(_parametros));

		for (Entry<String, String> entry : request.getHeaders().entrySet())
			if (!entry.getValue().isEmpty())
				http.addHeader(entry.getKey(), entry.getValue());

		HttpClient httpClient = null;

		try {

			httpClient = obterHttpClient(sslAuth, port);
			return tratarRetorno(httpClient.execute(http));

		} catch (Exception e) {
			throw e;
		} finally {
			if (httpClient != null)
				httpClient.getConnectionManager().shutdown();
		}
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @param ssl
	 * @return
	 * @throws Exception
	 */
	private String executeGet(String url, Integer port, Boolean ssl)
			throws Exception {

		return executeRequest(url, port, ssl, null, Method.GET);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @return
	 * @throws Exception
	 */
	public String executeGetSSLAuth(String url, Integer port) throws Exception {

		return executeGet(url, port, true);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public String executeGet(String url) throws Exception {

		return executeGet(url, null, false);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @param ssl
	 * @return
	 * @throws Exception
	 */
	private String executePut(String url, Integer port, Boolean ssl,
			List<NameValuePair> parametros) throws Exception {

		return executeRequest(url, port, ssl, parametros, Method.PUT);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @return
	 * @throws Exception
	 */
	public String executePutSSLAuth(String url, Integer port,
			List<NameValuePair> parametros) throws Exception {

		return executePut(url, port, true, parametros);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public String executePut(String url, List<NameValuePair> parametros)
			throws Exception {

		return executePut(url, null, false, parametros);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @param ssl
	 * @return
	 * @throws Exception
	 */
	private String executeDelete(String url, Integer port, Boolean ssl)
			throws Exception {

		return executeRequest(url, port, ssl, null, Method.DELETE);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @return
	 * @throws Exception
	 */
	public String executeDeleteSSLAuth(String url, Integer port)
			throws Exception {

		return executeDelete(url, port, true);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public String executeDelete(String url) throws Exception {

		return executeDelete(url, null, false);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @param ssl
	 * @return
	 * @throws Exception
	 */
	private String executePost(String url, Integer port, Boolean ssl,
			List<NameValuePair> parametros) throws Exception {

		return executeRequest(url, port, ssl, parametros, Method.POST);

	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param port
	 * @param parametros
	 * @return
	 * @throws Exception
	 */
	public String executePostSSLAuth(String url, Integer port,
			List<NameValuePair> parametros) throws Exception {

		return executePost(url, port, true, parametros);
	}

	/**
	 * 
	 * @author fantini
	 * @since 19/10/2012
	 * @param url
	 * @param parametros
	 * @return
	 * @throws Exception
	 */
	public String executePost(String url, List<NameValuePair> parametros)
			throws Exception {

		return executePost(url, null, false, parametros);
	}
}
