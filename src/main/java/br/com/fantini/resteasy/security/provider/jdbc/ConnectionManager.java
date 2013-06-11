package br.com.fantini.resteasy.security.provider.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class ConnectionManager {
			
	private static DataSource ds;
	
	public static synchronized DataSource getInstanceDS() throws NamingException {
		
		if (ds == null) {
			ds = (DataSource) new InitialContext().lookup("java:jdbc/restsecurity");
		}
		return ds;
	}
	
	public static Connection getConnection() throws SQLException, NamingException {
		return getInstanceDS().getConnection();
	}
}
