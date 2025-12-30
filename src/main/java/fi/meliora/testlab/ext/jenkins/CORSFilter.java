package fi.meliora.testlab.ext.jenkins;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;

/**
 * Adds CORS headers to Jenkins response. Adapted from CORS-filter and included in
 * this plugin because the original plugin is not published in public repositories.
 *
 * @author Meliora Ltd
 */
public class CORSFilter implements Filter {
    private final static Logger log = Logger.getLogger(CORSFilter.class.getName());

    private boolean enabled = false;
    private List<String> origins = null;     // by default, no origins allowed

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getOrigins() {
        return origins;
    }

    public void setOrigins(List<String> origins) {
        this.origins = origins;
    }

    private static final String CORS_HANDLE_OPTIONS_METHOD = System.getProperty("cors.options", "true");
    private static final String CORS_METHODS = System.getProperty("cors.methods", "GET, POST, PUT, DELETE");
    private static final String CORS_HEADERS = System.getProperty("cors.headers", "Authorization, .crumb, Origin, Jenkins-Crumb");
    private static final String CORS_CREDENTIALS = System.getProperty("cors.credentials", "true");

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if(enabled) {
            log.finest("doFilter: CORSFilter enabled for origins " + origins);

            if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
                if(origins != null && origins.size() > 0) {
                    final HttpServletRequest req = (HttpServletRequest)request;
                    final HttpServletResponse resp = (HttpServletResponse) response;

                    String origin = req.getHeader("Origin");
                    if(origin != null) {
                        log.finest("doFilter: CORSFilter processing request for Origin: " + origin);

                        //
                        // note: as the cors header supports only a single Origin value, we
                        //  support multiple values here by echoing back the valid Origin values
                        //  ourselves
                        //
                        if(origins.contains("*") || origins.contains(origin)) {
                            log.finest("doFilter: CORSFilter adding headers.");
                            resp.addHeader("Access-Control-Allow-Origin", URLEncoder.encode(origin, StandardCharsets.UTF_8.name()));
                            resp.addHeader("Access-Control-Allow-Methods", CORS_METHODS);
                            resp.addHeader("Access-Control-Allow-Headers", CORS_HEADERS);
                            resp.addHeader("Access-Control-Allow-Credentials", CORS_CREDENTIALS);
                            if(Boolean.valueOf(CORS_HANDLE_OPTIONS_METHOD)) {
                                if("OPTIONS".equals(req.getMethod())) {
                                    resp.setStatus(200);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            log.finest("doFilter: CORSFilter disabled.");
        }
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.fine("CORSFilter.init()");
    }

    @Override
    public void destroy() {
        log.fine("CORSFilter.destroy()");
    }
}
