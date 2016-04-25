package com.mycompany.myproject.authenticationhandler;

import com.day.crx.security.token.TokenUtil;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.jcr.AccessDeniedException;
import javax.jcr.LoginException;
import javax.jcr.Node;
//import javax.jcr.Property;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base32;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.osgi.framework.Constants;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.jcr.api.SlingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(metatype = true, immediate = true, label = "My Custom Authentication Handelr",
description="Authenticates User Against Citrix One Web Service")
@Service
/*@Properties({
    @Property(name = AuthenticationHandler.PATH_PROPERTY, value = "/"),
    @Property(name = Constants.SERVICE_DESCRIPTION, value = "My Custom Authentication Handler"),
    @Property(name = AuthenticationHandler.TYPE_PROPERTY, value = HttpServletRequest.FORM_AUTH, propertyPrivate = true)
})*/
	
public class otpAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler, AuthenticationFeedbackHandler
{
  private static final String REQUEST_METHOD = "POST";
  private static final String USER_NAME = "j_username";
  private static final String PASSWORD = "j_password";
  private static final String OTPCODE = "j_otpcode";
  private static final String SECRET_KEY = "secretKey";
  private static boolean isNewKey = false;
  private static final String HMAC_HASH_FUNCTION = "HmacSHA1";
  private static long timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30L);
  private static int keyModulus = (int)Math.pow(10.0D, 6.0D);
  @Reference
  private SlingRepository repository;
  static final String REQUEST_URL_SUFFIX = "/j_security_check";
  private final Logger log = LoggerFactory.getLogger(otpAuthenticationHandler.class);
   
  public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo)
  {
	return true;
   
  }
  
  public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response)
  {
	this.log.info("Log 1:");
	
	//AuthenticationInfo authinfo = new AuthenticationInfo("CUSTOM_AUTH","userid","pwd".toCharArray());
	
	//this.log.info("Log 1:"+request.getParameter(authinfo.getUser()));
	 
    if (("POST".equals(request.getMethod())) && (request.getRequestURI().endsWith("/j_security_check")))
    {
    	this.log.info("log 2");
      SimpleCredentials creds = new SimpleCredentials("ankitarastogi", "anki".toCharArray());
      try
      {
    	  
        Session session = this.repository.login(creds);
        if (session != null)
        {
          boolean is2StepAuthEnabled = check2StepAuthPreference(request.getParameter("j_username"), session);
          if (is2StepAuthEnabled)
          {
            String needNewKey = checkOrCreateSecurityKey(request.getParameter("j_username"), session);
            if ((needNewKey != null) && (needNewKey.length() > 0))
            {
              if (request.getParameter("j_otpcode").length() <= 0)
              {
                request.setAttribute("j_reason", "invalid_otp");
                session.logout();
                 
                return AuthenticationInfo.FAIL_AUTH;
              }
              boolean isSameCode = getCookie(request);
              if (!isSameCode)
              {
                if (checkCode(response, needNewKey, Long.parseLong(request.getParameter("j_otpcode")), new Date().getTime(), 23)) {
                  return createAuthenticationInfo(request, response, request.getParameter("j_username"));
                }
                request.setAttribute("j_reason", "invalid_otp");
                session.logout();
                return AuthenticationInfo.FAIL_AUTH;
              }
              request.setAttribute("j_reason", "invalid_otp");
              session.logout();
              return AuthenticationInfo.FAIL_AUTH;
            }
          }
          else
          {
            String key = checkOrCreateSecurityKey(request.getParameter("j_username"), session);
            return createAuthenticationInfo(request, response, request.getParameter("j_username"));
          }
        }
      }
      catch (LoginException e1)
      {
        e1.printStackTrace();
      }
      catch (RepositoryException e1)
      {
        e1.printStackTrace();
      }
      catch (Exception e)
      {
        e.printStackTrace();
      }
    }
    return null;
  }
   
  private boolean check2StepAuthPreference(String userId, Session session1)
    throws AccessDeniedException, UnsupportedRepositoryOperationException, RepositoryException
  {
    Session adminSession = this.repository.loginAdministrative(null);
     
    UserManager um = ((JackrabbitSession)adminSession).getUserManager();
    org.apache.jackrabbit.api.security.user.Authorizable authorizable = um.getAuthorizable(userId);
     
    boolean is2StepEnabled = false;
    try
    {
      if (adminSession.itemExists(authorizable.getPath() + "/preferences"))
      {
        Node pref = adminSession.getNode(authorizable.getPath() + "/preferences");
        if (pref.hasProperty("twostep"))
        {
          javax.jcr.Property references = pref.getProperty("twostep");
          String values = references.getValue().getString();
          if ((values != null) && (values.equals("Yes"))) {
            is2StepEnabled = true;
          } else {
            is2StepEnabled = false;
          }
        }
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    finally
    {
      if (adminSession != null) {
        adminSession.logout();
      }
    }
    return is2StepEnabled;
  }
   
  private AuthenticationInfo createAuthenticationInfo(HttpServletRequest request, HttpServletResponse response, String userId)
    throws RepositoryException
  {
    AuthenticationInfo authinfo = TokenUtil.createCredentials(request, response, this.repository, userId, true);
     
    return authinfo;
  }
   
  private String checkOrCreateSecurityKey(String userId, Session session)
    throws AccessDeniedException, UnsupportedRepositoryOperationException, RepositoryException
  {
    UserManager um = ((JackrabbitSession)session).getUserManager();
    Authorizable authorizable = um.getAuthorizable(userId);
     
    String key = null;
     
    String profilePath = authorizable.getPath() + "/profile";
     
    Node node = session.getNode(profilePath);
    if (node.hasProperty("secretKey"))
    {
      javax.jcr.Property references = node.getProperty("secretKey");
       
      String secretKey = references.getValue().getString();
      if ((secretKey != null) && (secretKey.length() > 0)) {
        key = secretKey;
      }
    }
    else
    {
      key = updateSecurityKey(authorizable, session);
    }
    return key;
  }
   
  private String updateSecurityKey(Authorizable userId, Session session)
    throws RepositoryException
  {
    Session adminSession = null;
     
    adminSession = this.repository.loginAdministrative(null);
    ValueFactory vf = session.getValueFactory();
    String userPath = userId.getPath();
    String userProfilePath = userPath + "/profile";
    String key = createSecretKey();
    try
    {
      Value val = vf.createValue(key);
      if (adminSession.itemExists(userProfilePath))
      {
        Node profile = adminSession.getNode(userProfilePath);
        profile.setProperty("secretKey", val);
        adminSession.save();
      }
      else
      {
        Node user = adminSession.getNode(userPath);
        Node profile = user.addNode("profile", "nt:unstructured");
        profile.setProperty("secretKey", val);
        adminSession.save();
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    finally
    {
      if (adminSession != null) {
        adminSession.logout();
      }
    }
    return key;
  }
   
  private String createSecretKey()
  {
    byte[] buffer = new byte[30];
     
 
    new Random().nextBytes(buffer);
     
    byte[] secretKey = Arrays.copyOf(buffer, 10);
    String generatedKey = new Base32().encodeToString(secretKey);
     
    isNewKey = true;
    return generatedKey;
  }
   
  public void dropCredentials(HttpServletRequest arg0, HttpServletResponse arg1)
    throws IOException
  {}
   
  public boolean requestCredentials(HttpServletRequest request, HttpServletResponse arg1)
    throws IOException
  {
    return false;
  }
   
  private boolean checkCode(HttpServletResponse response, String secret, long code, long timestamp, int window)
  {
    Base32 codec32 = new Base32();
    byte[] decodedKey = codec32.decode(secret);
     
    long timeWindow = timestamp / timeStepSizeInMillis;
    for (int i = -((window - 1) / 2); i <= window / 2; i++)
    {
      long hash = calculateCode(decodedKey, timeWindow + i);
      if (hash == code)
      {
        createCookie(response, code);
        return true;
      }
    }
    return false;
  }
   
  private void createCookie(HttpServletResponse response, long code)
  {
    Cookie cookie = new Cookie("validtoken", String.valueOf(code));
    cookie.setMaxAge(600);
    cookie.setPath("/");
    response.addCookie(cookie);
  }
   
  private int calculateCode(byte[] key, long tm)
  {
    byte[] data = new byte[8];
    long value = tm;
     
    int code = 0;
    for (int i = 8; i-- > 0; value >>>= 8) {
      data[i] = ((byte)(int)value);
    }
    SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
    try
    {
      Mac mac = Mac.getInstance("HmacSHA1");
       
      mac.init(signKey);
       
      byte[] hash = mac.doFinal(data);
       
      int offset = hash[(hash.length - 1)] & 0xF;
       
      long truncatedHash = 0L;
      for (int i = 0; i < 4; i++)
      {
        truncatedHash <<= 8;
         
        truncatedHash |= hash[(offset + i)] & 0xFF;
      }
      truncatedHash &= 0x7FFFFFFF;
      truncatedHash %= keyModulus;
      code = (int)truncatedHash;
    }
    catch (Exception ex) {}
    return code;
  }
   
  private boolean getCookie(HttpServletRequest request)
  {
    Cookie[] cookies = request.getCookies();
    boolean foundCookie = false;
    String otp = request.getParameter("j_otpcode");
    for (int i = 0; i < cookies.length; i++)
    {
      Cookie cookie1 = cookies[i];
      if ((cookie1.getName().equals("validtoken")) && 
        (cookie1.getValue().equals(otp))) {
        foundCookie = true;
      }
    }
    return foundCookie;
  }
   
  protected void bindRepository(SlingRepository paramSlingRepository)
  {
    this.repository = paramSlingRepository;
  }
   
  protected void unbindRepository(SlingRepository paramSlingRepository)
  {
    if (this.repository == paramSlingRepository) {
      this.repository = null;
    }
  }
}
