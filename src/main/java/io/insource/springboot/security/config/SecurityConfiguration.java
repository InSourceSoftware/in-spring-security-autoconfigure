package io.insource.springboot.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Configuration properties for opinionated security.
 */
@ConfigurationProperties("security.auth")
public class SecurityConfiguration {
    /**
     * API login authentication.
     */
    private ApiLoginAuthentication api = new ApiLoginAuthentication();

    /**
     * Basic authentication.
     */
    private BasicAuthentication basic = new BasicAuthentication();

    /**
     * CSRF configuration.
     */
    private Csrf csrf = new Csrf();

    /**
     * Form login authentication.
     */
    private FormLoginAuthentication form = new FormLoginAuthentication();

    /**
     * Siteminder-style pre-authentication.
     */
    private PreAuthentication pre = new PreAuthentication();

    /**
     * Token-based pre-authentication.
     */
    private TokenAuthentication token = new TokenAuthentication();

    public ApiLoginAuthentication getApi() {
        return api;
    }

    public void setApi(ApiLoginAuthentication api) {
        this.api = api;
    }

    public BasicAuthentication getBasic() {
        return basic;
    }

    public void setBasic(BasicAuthentication basic) {
        this.basic = basic;
    }

    public Csrf getCsrf() {
        return csrf;
    }

    public void setCsrf(Csrf csrf) {
        this.csrf = csrf;
    }

    public FormLoginAuthentication getForm() {
        return form;
    }

    public void setForm(FormLoginAuthentication form) {
        this.form = form;
    }

    public PreAuthentication getPre() {
        return pre;
    }

    public void setPre(PreAuthentication pre) {
        this.pre = pre;
    }

    public TokenAuthentication getToken() {
        return token;
    }

    public void setToken(TokenAuthentication token) {
        this.token = token;
    }

    /**
     * API login authentication.
     */
    public static class ApiLoginAuthentication {
        /**
         * Enable API login authentication auto-configuration.
         */
        private boolean enabled = false;

        /**
         * Path spec to match for this security configuration.
         */
        private String path = "/**";

        /**
         * Comma-separated list of paths to ignore.
         */
        private String[] ignore = new String[] {};

        /**
         * Authorization realm name.
         */
        private String realm = "Spring";

        /**
         * Username field in login API request.
         */
        private String usernameParameter = "username";

        /**
         * Password field in login API request.
         */
        private String passwordParameter = "password";

        /**
         * Login processing URL used to process POST requests to log in.
         */
        private String loginUrl = "/login";

        /**
         * Logout processing URL used to process POST requests to log out.
         */
        private String logoutUrl = "/logout";

        /**
         * Redirect URL used for login success.
         */
        private String loginRedirectUrl = "/";

        /**
         * Redirect URL used for logout success.
         */
        private String logoutRedirectUrl = "/";

        /**
         * Property or method on UserDetails to retrieve per-user salt value.
         * Leave empty to disable.
         */
        private String saltProperty = "salt";

        /**
         * Anonymous user.
         */
        private User anonymous = new User("anonymous", null, Collections.singletonList("ROLE_ANONYMOUS"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String[] getIgnore() {
            return ignore;
        }

        public void setIgnore(String[] ignore) {
            this.ignore = ignore;
        }

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public String getUsernameParameter() {
            return usernameParameter;
        }

        public void setUsernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter;
        }

        public String getPasswordParameter() {
            return passwordParameter;
        }

        public void setPasswordParameter(String passwordParameter) {
            this.passwordParameter = passwordParameter;
        }

        public String getLoginUrl() {
            return loginUrl;
        }

        public void setLoginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        public String getLogoutUrl() {
            return logoutUrl;
        }

        public void setLogoutUrl(String logoutUrl) {
            this.logoutUrl = logoutUrl;
        }

        public String getLoginRedirectUrl() {
            return loginRedirectUrl;
        }

        public void setLoginRedirectUrl(String loginRedirectUrl) {
            this.loginRedirectUrl = loginRedirectUrl;
        }

        public String getLogoutRedirectUrl() {
            return logoutRedirectUrl;
        }

        public void setLogoutRedirectUrl(String logoutRedirectUrl) {
            this.logoutRedirectUrl = logoutRedirectUrl;
        }

        public String getSaltProperty() {
            return saltProperty;
        }

        public void setSaltProperty(String saltProperty) {
            this.saltProperty = saltProperty;
        }

        public User getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(User anonymous) {
            this.anonymous = anonymous;
        }
    }

    /**
     * Basic authentication.
     */
    public static class BasicAuthentication {
        /**
         * Enable basic authentication auto-configuration.
         */
        private boolean enabled = false;

        /**
         * Path spec to match for this security configuration.
         */
        private String path = "/**";

        /**
         * Comma-separated list of paths to ignore.
         */
        private String[] ignore = new String[] {};

        /**
         * HTTP basic realm name.
         */
        private String realm = "Spring";

        /**
         * Property or method on UserDetails to retrieve per-user salt value.
         * Leave empty to disable.
         */
        private String saltProperty = "salt";

        /**
         * List of users.
         */
        private List<User> users = new ArrayList<>(Collections.singletonList(new User()));

        /**
         * Anonymous user.
         */
        private User anonymous = new User("anonymous", null, Collections.singletonList("ROLE_ANONYMOUS"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String[] getIgnore() {
            return ignore;
        }

        public void setIgnore(String[] ignore) {
            this.ignore = ignore;
        }

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public List<User> getUsers() {
            return users;
        }

        public void setUsers(List<User> users) {
            this.users = users;
        }

        public String getSaltProperty() {
            return saltProperty;
        }

        public void setSaltProperty(String saltProperty) {
            this.saltProperty = saltProperty;
        }

        public User getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(User anonymous) {
            this.anonymous = anonymous;
        }
    }

    /**
     * CSRF configuration.
     */
    private class Csrf {
        /**
         * Enable CSRF endpoint.
         */
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * Form login authentication.
     */
    public static class FormLoginAuthentication {
        /**
         * Enable form login authentication auto-configuration.
         */
        private boolean enabled = false;

        /**
         * Path spec to match for this security configuration.
         */
        private String path = "/**";

        /**
         * Comma-separated list of paths to ignore.
         */
        private String[] ignore = new String[] {};

        /**
         * Username parameter in login API request.
         */
        private String usernameParameter = "username";

        /**
         * Password parameter in login API request.
         */
        private String passwordParameter = "password";

        /**
         * Login processing URL used to process POST requests to log in.
         */
        private String loginUrl = "/login";

        /**
         * Logout processing URL used to process POST requests to log out.
         */
        private String logoutUrl = "/logout";

        /**
         * Redirect URL used for login success.
         */
        private String loginRedirectUrl = "/";

        /**
         * Redirect URL used for logout success.
         */
        private String logoutRedirectUrl = "/";

        /**
         * Property or method on UserDetails to retrieve per-user salt value.
         * Leave empty to disable.
         */
        private String saltProperty = "salt";

        /**
         * Anonymous user.
         */
        private User anonymous = new User("anonymous", null, Collections.singletonList("ROLE_ANONYMOUS"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String[] getIgnore() {
            return ignore;
        }

        public void setIgnore(String[] ignore) {
            this.ignore = ignore;
        }

        public String getUsernameParameter() {
            return usernameParameter;
        }

        public void setUsernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter;
        }

        public String getPasswordParameter() {
            return passwordParameter;
        }

        public void setPasswordParameter(String passwordParameter) {
            this.passwordParameter = passwordParameter;
        }

        public String getLoginUrl() {
            return loginUrl;
        }

        public void setLoginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        public String getLogoutUrl() {
            return logoutUrl;
        }

        public void setLogoutUrl(String logoutUrl) {
            this.logoutUrl = logoutUrl;
        }

        public String getLoginRedirectUrl() {
            return loginRedirectUrl;
        }

        public void setLoginRedirectUrl(String loginRedirectUrl) {
            this.loginRedirectUrl = loginRedirectUrl;
        }

        public String getLogoutRedirectUrl() {
            return logoutRedirectUrl;
        }

        public void setLogoutRedirectUrl(String logoutRedirectUrl) {
            this.logoutRedirectUrl = logoutRedirectUrl;
        }

        public String getSaltProperty() {
            return saltProperty;
        }

        public void setSaltProperty(String saltProperty) {
            this.saltProperty = saltProperty;
        }

        public User getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(User anonymous) {
            this.anonymous = anonymous;
        }
    }

    /**
     * Siteminder-style pre-authentication.
     */
    public static class PreAuthentication {
        /**
         * Enable Siteminder-style pre-authentication auto-configuration.
         */
        private boolean enabled = false;

        /**
         * Path spec to match for this security configuration.
         */
        private String path = "/**";

        /**
         * Comma-separated list of paths to ignore.
         */
        private String[] ignore = new String[] {};

        /**
         * Authorization realm name.
         */
        private String realm = "Spring";

        /**
         * Principal request header name.
         */
        private String header = "SM_USER";

        /**
         * Anonymous user.
         */
        private User anonymous = new User("anonymous", null, Collections.singletonList("ROLE_ANONYMOUS"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String[] getIgnore() {
            return ignore;
        }

        public void setIgnore(String[] ignore) {
            this.ignore = ignore;
        }

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public User getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(User anonymous) {
            this.anonymous = anonymous;
        }
    }

    /**
     * Token-based pre-authentication.
     */
    public static class TokenAuthentication {
        /**
         * Enable token-based pre-authentication auto-configuration.
         */
        private boolean enabled = false;

        /**
         * Path spec to match for this security configuration.
         */
        private String path = "/**";

        /**
         * Comma-separated list of paths to ignore.
         */
        private String[] ignore = new String[] {};

        /**
         * Authorization realm name.
         */
        private String realm = "Spring";

        /**
         * Principal request header name.
         */
        private String header = "Authorization";

        /**
         * Anonymous user.
         */
        private User anonymous = new User("anonymous", null, Collections.singletonList("ROLE_ANONYMOUS"));

        /**
         * Cache name used to store user details.
         */
        private String cache = "users";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String[] getIgnore() {
            return ignore;
        }

        public void setIgnore(String[] ignore) {
            this.ignore = ignore;
        }

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public User getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(User anonymous) {
            this.anonymous = anonymous;
        }

        public String getCache() {
            return cache;
        }

        public void setCache(String cache) {
            this.cache = cache;
        }
    }

    /**
     * Authenticated user credentials.
     */
    public static class User {
        /**
         * Default user name.
         */
        private String name;

        /**
         * Password for the default user name.
         */
        private String password;

        /**
         * Granted roles for the default user name.
         */
        private List<String> role;

        public User() {
            this("user", "password", Collections.singletonList("USER"));
        }

        public User(String name, String password, List<String> role) {
            this.name = name;
            this.password = password;
            this.role = new ArrayList<>(role);
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public List<String> getRole() {
            return role;
        }

        public void setRole(List<String> role) {
            this.role = role;
        }
    }
}
