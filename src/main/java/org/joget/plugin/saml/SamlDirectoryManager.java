package org.joget.plugin.saml;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.*;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @editor akash.johnthadeus <br>
 * SAML SP implementation adapted from https://github.com/onelogin/java-saml/tree/v1.1.2
 */
public class SamlDirectoryManager extends SecureDirectoryManager {

    @Override
    public String getName() {
        return "Al Shirawi SAML Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for Al Shirawi SAML 2.0";
    }

    @Override
    public String getVersion() {
        return "6.0.3";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        return super.getDirectoryManagerImpl(properties);
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String acsUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            acsUrl += ":" + request.getServerPort();
        }
        acsUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.saml.SamlDirectoryManager/service";
        String entityId = acsUrl;

        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/samlDirectoryManager.json", new String[]{entityId, acsUrl, usJson, addOnJson}, true, "messages/samlDirectoryManager");
        return json;
    }

    @Override
    public String getLabel() {
        return "SAML Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String action = request.getParameter("action");
        if ("dmOptions".equals(action)) {
            super.webService(request, response);
        } else if (request.getParameter("SAMLResponse") != null) {
            doLogin(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_NO_CONTENT);
        }

    }

    void doLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {

            // read from properties
            DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
            SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

            Boolean debug = Boolean.parseBoolean(dmImpl.getPropertyString("debugMode"));

            String certificate = dmImpl.getPropertyString("certificate");

            if (certificate == null || certificate.isEmpty()) {
                int i = 1;
                while (true) {
                    String dmKey = "dm" + i;
                    Object dmObj = dmImpl.getProperty(dmKey);
                    // Exit loop if no more dm entries
                    if (dmObj == null) {
                        throw new CertificateException("IDP certificate is missing");
                    }

                    if (dmObj instanceof Map) {
                        Map<String, Object> dmMap = (Map<String, Object>) dmObj;
                        Object classNameObj = dmMap.get("className");

                        if ("org.joget.plugin.saml.SamlDirectoryManager".equals(classNameObj)) {
                            Object propsObj = dmMap.get("properties");
                            if (propsObj instanceof Map) {
                                Map<String, Object> propertiesMap = (Map<String, Object>) propsObj;

                                Object debugObj = propertiesMap.get("debugMode");
                                if (debugObj != null) {
                                    debug = Boolean.parseBoolean(debugObj.toString());
                                }

                                Object cert = propertiesMap.get("certificate");
                                if (cert != null && !cert.toString().isEmpty()) {
                                    certificate = cert.toString();
                                    if (debug)
                                        LogUtil.info("Certificate: ", certificate);
                                    break;
                                } else {
                                    throw new CertificateException("IDP certificate is missing");
                                }
                            } else {
                                LogUtil.info(dmKey + " properties", " is not a Map.");
                            }
                        }
                    }
                    i++;
                }
            }


//            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
            boolean userProvisioningEnabled = false;

            String attrEmail = dmImpl.getPropertyString("attrEmail");
            String attrFirstName = dmImpl.getPropertyString("attrFirstName");
            String attrLastName = dmImpl.getPropertyString("attrLastName");

            if (certificate == null || certificate.isEmpty()) {
                throw new CertificateException("IDP certificate is missing");
            }

            AccountSettings accountSettings = new AccountSettings();
            accountSettings.setCertificate(certificate);
            SamlResponse samlResponse = new SamlResponse(accountSettings);
            samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));
            samlResponse.setDestinationUrl(request.getRequestURL().toString());

            if (samlResponse.isValid()) {
                if (debug) {
                    LogUtil.info(getClassName() + " : attributes : ", samlResponse.getAttributes().toString());
                }
                String username = samlResponse.getNameId();
                // get user
//                User user = dmImpl.getUserByUsername(username);
                User user = getUserByEmail(username, debug);
                if (user == null && userProvisioningEnabled) {
                    // user does not exist, provision
                    user = new User();
                    user.setId(username);
                    user.setUsername(username);
                    user.setTimeZone("0");
                    user.setActive(1);
                    attrEmail = (attrEmail != null && !attrEmail.isEmpty()) ? attrEmail : "email";
                    String email = samlResponse.getAttribute(attrEmail);
                    if (email != null) {
                        if (email.startsWith("[")) {
                            email = email.substring(1, email.length() - 1);
                        }
                        user.setEmail(email);
                    }
                    attrFirstName = (attrFirstName != null && !attrFirstName.isEmpty()) ? attrFirstName : "User.FirstName";
                    String firstName = samlResponse.getAttribute(attrFirstName);
                    if (firstName != null) {
                        if (firstName.startsWith("[")) {
                            firstName = firstName.substring(1, firstName.length() - 1);
                        }
                        user.setFirstName(firstName);
                    }
                    attrLastName = (attrLastName != null && !attrLastName.isEmpty()) ? attrLastName : "User.LastName";
                    String lastName = samlResponse.getAttribute(attrLastName);
                    if (lastName != null) {
                        if (lastName.startsWith("[")) {
                            lastName = lastName.substring(1, lastName.length() - 1);
                        }
                        user.setLastName(lastName);
                    }
                    // set role
                    RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
                    Set roleSet = new HashSet();
                    Role r = roleDao.getRole("ROLE_USER");
                    if (r != null) {
                        roleSet.add(r);
                    }
                    user.setRoles(roleSet);
                    // add user
                    UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                    userDao.addUser(user);
                } else if (user == null && !userProvisioningEnabled) {
                    request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception("Required information is missing. Please contact IT team for further support"));
                    response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                    return;
                }

                if ("EMAIL_MULTIPLE_USERS".equals(user.getId())) {
                    request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception("Multiple accounts are linked to this email address. Please contact IT team for further support"));
                    response.sendRedirect(request.getContextPath() + "/web/login?login_error=multi");
                    return;
                }

                username = user.getUsername();

                // verify license
                PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
                DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
                DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
                authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());

                // get authorities
                Collection<Role> roles = dm.getUserRoles(username);
                List<GrantedAuthority> gaList = new ArrayList<>();
                if (roles != null && !roles.isEmpty()) {
                    for (Role role : roles) {
                        GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                        gaList.add(ga);
                    }
                }

                // login user
                UserDetails details = new WorkflowUserDetails(user);
                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
                result.setDetails(details);
                SecurityContextHolder.getContext().setAuthentication(result);

                String ip = "";
                if (request != null) {
                    ip = AppUtil.getClientIp(request);
                }

                // add audit trail
                LogUtil.info(getClass().getName(), "Authentication for user " + username + " (" + ip + ") : " + true);
                WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + "(" + ip + "): " + true);

                // redirect
                String relayState = request.getParameter("RelayState");
                if (relayState != null && !relayState.isEmpty()) {
                    response.sendRedirect(relayState);
                } else {
                    response.sendRedirect(request.getContextPath());
                }
            } else {
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception("Required information is missing. Please contact IT team for further support"));
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
            }
        } catch (Exception ex) {
            LogUtil.error(getClass().getName(), ex, "Error in SAML login");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }

    }

    private User getUserByEmail(String email, Boolean debug) {
        ExtDirectoryManager directoryManager = (ExtDirectoryManager) AppUtil.getApplicationContext().getBean("directoryManager");
        Collection<User> userListAll = directoryManager.getUsers(email, null, null, null, null, null, null, "firstName", false, null, null);
        Collection<User> userList = new ArrayList<>();

        for (User u : userListAll) {
            if(email.equals(u.getEmail())){
                userList.add(u);
            }
        }

        if (userList == null || userList.isEmpty()) {
            if (debug)
                LogUtil.warn(getClassName(), "No account is linked to this email address : " + email);
            return null; // No users found
        }
        if (userList.size() == 1) {
            // Exactly one user found
            User singleUser = userList.iterator().next();
            if (debug)
                LogUtil.info(getClassName(), singleUser.getUsername() + " : account is linked to this email address : " + email);
            return singleUser;
        } else {
            // More than one user found
            User multiUser = new User();
            multiUser.setId("EMAIL_MULTIPLE_USERS");
            if (debug)
                LogUtil.info(getClassName(), "Multiple accounts are linked to this email address : " + email);
            return multiUser;
        }

    }

}
