package comp3911.cwk2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;

public class AppServer {
    public static void main(String[] args) throws Exception {
        Log.setLog(new StdErrLog());

        Server server = new Server();

        // SSL Context Factory
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath("keystore.jks");
        sslContextFactory.setKeyStorePassword("password");
        sslContextFactory.setKeyManagerPassword("password");
        
        // HTTP Configuration
        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setSecureScheme("https");
        httpConfig.setSecurePort(8443);
        
        HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
        httpsConfig.addCustomizer(new SecureRequestCustomizer(true));
        
        // SSL Connector
        ServerConnector sslConnector = new ServerConnector(server,
            new SslConnectionFactory(sslContextFactory, "http/1.1"),
            new HttpConnectionFactory(httpsConfig));
        sslConnector.setPort(8443);
        
        server.addConnector(sslConnector);
        
        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(AppServlet.class, "/*");

        // Add security headers using HandlerWrapper
        HandlerWrapper securityHandler = new HandlerWrapper() {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest,
                             javax.servlet.http.HttpServletRequest request,
                             javax.servlet.http.HttpServletResponse response) 
                    throws java.io.IOException, javax.servlet.ServletException {
                
                // Set security headers
                response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
                response.setHeader("X-Content-Type-Options", "nosniff");
                response.setHeader("X-Frame-Options", "DENY");
                // CSP for Markdown/Bootstrap styling
                response.setHeader("Content-Security-Policy", 
                    "default-src 'self'; " +
                    "style-src 'self' 'unsafe-inline' " +
                    "https://stackpath.bootstrapcdn.com " +
                    "https://cdn.jsdelivr.net " +
                    "https://maxcdn.bootstrapcdn.com; " +
                    "script-src 'self' 'unsafe-inline' " +
                    "https://code.jquery.com " +
                    "https://stackpath.bootstrapcdn.com " +
                    "https://maxcdn.bootstrapcdn.com " +
                    "https://cdn.jsdelivr.net; " +
                    "font-src 'self' " +
                    "https://stackpath.bootstrapcdn.com " +
                    "https://maxcdn.bootstrapcdn.com " +
                    "data:; " +
                    "img-src 'self' data:;");
                
                response.setContentType("text/html;charset=utf-8");
                
                if (!baseRequest.isHandled()) {
                    super.handle(target, baseRequest, request, response);
                }
            }
        };
        
        securityHandler.setHandler(handler);
        server.setHandler(securityHandler);

        server.start();
        server.join();
    }
}