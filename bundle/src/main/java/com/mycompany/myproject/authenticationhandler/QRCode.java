package com.mycompany.myproject.authenticationhandler;
 
import com.adobe.granite.security.user.UserProperties;
import com.adobe.granite.security.user.UserPropertiesManager;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import org.apache.felix.scr.annotations.sling.SlingServlet;
 
@SlingServlet(paths="/bin/qrcode", methods = "GET", metatype=true)
 
 
public class QRCode extends SlingAllMethodsServlet
{
  public static final String GURL = "https://www.google.com/chart?chs=250x250&cht=qr&chl=otpauth://totp/";
  private final Logger log = LoggerFactory.getLogger(QRCode.class);
   
  protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
    throws IOException
  {
    String userId = "";
    String secretKey = "";
    try
    {
    	
      ResourceResolver resourceResolver = request.getResourceResolver();
       
 
      Authorizable auth = (Authorizable)resourceResolver.adaptTo(Authorizable.class);
      UserPropertiesManager upm = (UserPropertiesManager)resourceResolver.adaptTo(UserPropertiesManager.class);
      if (upm != null)
      {
        UserProperties profile = upm.getUserProperties(auth, "profile");
        if (profile != null) {
          secretKey = (String)profile.getProperty("secretKey", "", String.class);
        }
      }
      userId = auth.getID();
       
      String url = userId + "%3Fsecret%3D" + secretKey;
       
      URL qrURL = new URL("https://www.google.com/chart?chs=250x250&cht=qr&chl=otpauth://totp/" + url);
      URLConnection conn = qrURL.openConnection();
       
      response.setContentType("image/png");
      response.setStatus(200);
       
 
      InputStream is = conn.getInputStream();
      BufferedInputStream bis = new BufferedInputStream(is);
      OutputStream os = response.getOutputStream();
      BufferedOutputStream bos = new BufferedOutputStream(os);
      byte[] buff = new byte[8192];
      int sz = 0;
      while ((sz = bis.read(buff)) != -1) {
        bos.write(buff, 0, sz);
      }
      bos.flush();
    }
    catch (Exception e)
    {
      this.log.error(e.getMessage());
      e.printStackTrace();
    }
  }
}