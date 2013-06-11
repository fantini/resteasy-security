package security.provider.jdbc;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import security.provider.dto.LogWSDTO;



public class JDBCSecurity {
	
	public Long getTransacao() throws Exception {
		Connection con = null;
		Long transacao = null;
		try {
			con = ConnectionManager.getConnection();
			PreparedStatement pstmt = con.prepareStatement("SELECT NEXTVAL('SA_REST.TRANSACAO_SEQ') AS TRANSACAO");
				
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				transacao = rs.getLong("TRANSACAO");
			}
			rs.close();
			pstmt.close();
			con.close();
		} catch (Exception e) {
			throw e;
		} finally {
			if (con != null) {
				con.close();
			}
		}
		return transacao;
		
	}
	
	public String getSecretKey(String id) throws Exception {
		Connection con = null;
		String signature = null;
		try {
			con = ConnectionManager.getConnection();
			PreparedStatement pstmt = con.prepareStatement("SELECT KEY FROM SA_REST.TB_USER WHERE ID = ?");
			pstmt.setInt(1, Integer.valueOf(id));
			pstmt.setMaxRows(1);
				
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				signature = rs.getString("KEY");
			}
			rs.close();
			pstmt.close();
			con.close();
		} catch (Exception e) {
			throw e;
		} finally {
			if (con != null) {
				con.close();
			}
		}
		return signature;
		
	}
	
	public List<String> getRoles(String id) throws Exception {
		Connection con = null;
		List<String> roles = new ArrayList<String>();
		try {
			con = ConnectionManager.getConnection();
			PreparedStatement pstmt = con.prepareStatement("SELECT NAME FROM SA_REST.TB_USERROLE LEFT JOIN SA_REST.TB_ROLE ON ID = ROLE_ID WHERE USER_ID = ?");
			pstmt.setInt(1, Integer.valueOf(id));
				
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				roles.add(rs.getString("NAME"));
			}
			rs.close();
			pstmt.close();
			con.close();
		} catch (Exception e) {
			throw e;
		} finally {
			if (con != null) {
				con.close();
			}
		}
		return roles;
		
	}	
	
	public void logWs(LogWSDTO obj) {
		Connection con = null;
		try {
			con = ConnectionManager.getConnection();
			StringBuilder ss = new StringBuilder();
			StringBuilder interrogacoes = new StringBuilder();
			ss.append("INSERT INTO SA_REST.TB_LOGWS(");			
			boolean poeVirgula = false;			
			Object valor;
			
			Method[] methods = obj.getClass().getDeclaredMethods();
			
			for(Method method: methods) {
				if (method.getName().startsWith("get")) {
					valor = method.invoke(obj);
					if (valor != null) {
						if (poeVirgula) {
							ss.append(",");interrogacoes.append(",");
						}
						interrogacoes.append("?");
						ss.append(method.getName().substring(3).toLowerCase());
						poeVirgula = true;
					}
				}
			}
			
			ss.append(") VALUES (");
			ss.append(interrogacoes);
			ss.append(")");
			
			PreparedStatement q = con.prepareStatement(ss.toString());
			
			int x = 1;
			
			for(Method method: methods) {
				if (method.getName().startsWith("get")) {
					valor = method.invoke(obj);
					if (valor != null) {
						if (valor instanceof Date)
							q.setTimestamp(x++, new Timestamp(((Date)valor).getTime()));
						else
							q.setObject(x++, valor);
					}
				}
			}
			
			q.executeUpdate();
			q.close();
			con.close();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
