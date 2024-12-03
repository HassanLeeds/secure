package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity.TransportGuarantee;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;   
import java.util.Base64;

@ServletSecurity(
    @HttpConstraint(transportGuarantee = TransportGuarantee.CONFIDENTIAL)
)
@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "SELECT * FROM user WHERE username = ? AND password_hash = ?";
  private static final String GET_SALT_QUERY = "SELECT salt FROM user WHERE username = ?";
  private static final String SEARCH_QUERY = "SELECT * FROM patient WHERE surname = ? COLLATE NOCASE";
  private static final Map<String, Integer> loginAttempts = new HashMap<>();
  private static final Map<String, Long> lockoutTime = new HashMap<>();

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException {
      String username = request.getParameter("username");
      String password = request.getParameter("password");
      String surname = request.getParameter("surname");

      try {
        if (authenticated(username, password)) {
          Map<String, Object> model = new HashMap<>();
          model.put("records", searchResults(surname));
          Template template = fm.getTemplate("details.html");
          template.process(model, response.getWriter());
        }
        else {
          Map<String, Object> model = new HashMap<>();
          if (lockAccount(username)) {
              model.put("lockout", true);
              long remainingTime = (lockoutTime.get(username) - System.currentTimeMillis()) / 1000;
              model.put("countdown", remainingTime);
          }
          Template template = fm.getTemplate("invalid.html");
          template.process(model, response.getWriter());
        }
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_OK);
      }
      catch (Exception error) {
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      }
    }
  
  //Password Hashing
  private String getUserSalt(String username) throws SQLException {
    try (PreparedStatement stmt = database.prepareStatement(GET_SALT_QUERY)) {
      stmt.setString(1, username);
      ResultSet results = stmt.executeQuery();
      if (results.next()) {
          return results.getString("salt");
      }
      return null;
    }
  }

  private String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(Base64.getDecoder().decode(salt));
    byte[] hashedPassword = md.digest(password.getBytes());
    return Base64.getEncoder().encodeToString(hashedPassword);
  }

  private boolean authenticated(String username, String password) throws SQLException {
    if (lockAccount(username)) {
        return false;
    }
    
    try {
        String salt = getUserSalt(username);
        if (salt == null) {
            incrementFailedAttempts(username);
            return false;
        }

        String hashedPassword = hashPassword(password, salt);

        try (PreparedStatement stmt = database.prepareStatement(AUTH_QUERY)) {
            stmt.setString(1, username);
            stmt.setString(2, hashedPassword);
            ResultSet results = stmt.executeQuery();
            boolean authenticated = results.next();
            
            if (authenticated) {
                loginAttempts.put(username, 0);
            } else {
                incrementFailedAttempts(username);
            }
            
            return authenticated;
        }
    } catch (NoSuchAlgorithmException e) {
        throw new SQLException("Hashing algorithm not available", e);
    }
  } 

  private boolean lockAccount(String username) {
      Long lockoutEnd = lockoutTime.get(username);
      return lockoutEnd != null && lockoutEnd > System.currentTimeMillis();
  }

  private void incrementFailedAttempts(String username) {
      int attempts = loginAttempts.getOrDefault(username, 0) + 1;
      loginAttempts.put(username, attempts);
      if (attempts >= 5) {
          lockoutTime.put(username, System.currentTimeMillis() + 5 * 60 * 1000);
      }
  }

  // Sql Injections
  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    try (PreparedStatement stmt = database.prepareStatement(SEARCH_QUERY)) {
      stmt.setString(1, surname);
      try (ResultSet results = stmt.executeQuery()) {
        while (results.next()) {
          Record rec = new Record();
          rec.setSurname(results.getString(2));
          rec.setForename(results.getString(3));
          rec.setAddress(results.getString(4));
          rec.setDateOfBirth(results.getString(5));
          rec.setDoctorId(results.getString(6));
          rec.setDiagnosis(results.getString(7));
          records.add(rec);
        }
      }
    }
    return records;
  }
}


