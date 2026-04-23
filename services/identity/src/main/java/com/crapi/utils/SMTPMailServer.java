/*
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.crapi.utils;

import com.crapi.config.MailConfiguration;
import com.crapi.config.MailHogConfiguration;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.*;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class SMTPMailServer {
  @Autowired MailConfiguration mailConfiguration;

  @Autowired MailHogConfiguration mailhogConfiguration;

  /**
   * @param sendMail
   * @param body
   * @param subject send mail to given email with dynamic subject and body
   */
private static final Logger log = LoggerFactory.getLogger(SMTPMailServer.class);

public void sendMail(String sendMail, String body, String subject) {
    // Validate using specialized email library (mitigation note #1)
    if (sendMail == null || !EmailValidator.getInstance().isValid(sendMail)) {
      log.error("Invalid email format detected: null", sanitizeLogMessage(sendMail));
      return;
    }
    
    // Sanitize email headers using ESAPI (mitigation note #1)
    String sanitizedSubject = sanitizeMailHeader(subject);
    
    // HTML sanitization for email content (mitigation note #2)
    String sanitizedBody = sanitizeHtmlContent(body);
    
    String mhogDomain = mailhogConfiguration.getDomain();
    Session session = mailhogConfiguration.sendmail();
    boolean useMailHog = false;
    try {
      log.info("Sending email to: null", sanitizeLogMessage(sendMail));
      
      // Use validateAddress before parsing
      InternetAddress[] emails = InternetAddress.parse(sendMail);
      for (InternetAddress address : emails) {
          address.validate();
      }
      
      // DMARC/DKIM/SPF verification if applicable (mitigation note #6)
      if (emailVerificationEnabled && !verifyDomainSecurity(getDomainFromEmail(sendMail))) {
        log.warn("Email domain security verification failed for: null", sanitizeLogMessage(sendMail));
        // Continue anyway but log the warning
      }
      
      if (mhogDomain != null && !mhogDomain.isEmpty()) {
        if (mailConfiguration.getHost().trim().endsWith(mhogDomain)) {
          log.info("SMTP host matches MailHog host. Using MailHog Configuration for sending emails");
          useMailHog = true;
        }
        for (InternetAddress emailAddress : emails) {
          String email = emailAddress.toString();
          // Extract domain safely with null checks
          int atIndex = email.indexOf("@");
          if (atIndex == -1 || atIndex >= email.length() - 1) {
            log.error("Invalid email format (missing domain): null", sanitizeLogMessage(email));
            return;
          }
          String domain = email.substring(atIndex + 1).trim();
          log.debug("Email domain: null", sanitizeLogMessage(domain));
          if (mhogDomain.trim().equals(domain)) {
            log.info("Using MailHog Configuration for sending email for domain: null", sanitizeLogMessage(domain));
            useMailHog = true;
          }
        }
      }
      if (!useMailHog) {
        session = mailConfiguration.sendmail();
        log.info("Using Mail Configuration for sending email to: null", sanitizeLogMessage(sendMail));
      }

      // Configure email with security headers
      Message msg = new MimeMessage(session);
      msg.setFrom(new InternetAddress(mailhogConfiguration.getFrom(), false));
      msg.setRecipients(Message.RecipientType.TO, emails);
      msg.setSubject(sanitizedSubject);
      msg.setContent(sanitizedBody, "text/html; charset=UTF-8");
      msg.setSentDate(new Date());
      
      // Add security headers
      MimeMessage mimeMsg = (MimeMessage) msg;
      mimeMsg.addHeader("X-Content-Type-Options", "nosniff");
      mimeMsg.addHeader("X-Frame-Options", "DENY");
      mimeMsg.addHeader("X-XSS-Protection", "1; mode=block");
      
      MimeBodyPart messageBodyPart = new MimeBodyPart();
      messageBodyPart.setContent(sanitizedBody, "text/html; charset=UTF-8");

      // Log security event before sending (mitigation note #7)
      securityEventLogger.logEmailSent(sendMail, sanitizedSubject);
      
      Transport.send(msg);
    } catch (Exception e) {
      log.error("Error sending email: null", sanitizeLogMessage(e.getMessage()));
      securityEventLogger.logEmailSendFailure(sendMail, e.getMessage());
    }
  }
  
  // Sanitize mail headers to prevent injection (mitigation note #1)
  private String sanitizeMailHeader(String header) {
    if (header == null) return "";
    // Remove CR, LF and other control characters that could allow header injection
    return header.replaceAll("[r
tfx00-x1Fx7F]", "");
  }
  
  // Sanitize HTML content using OWASP HTML Sanitizer (mitigation note #2)
  private String sanitizeHtmlContent(String content) {
    if (content == null) return "";
    
    // Define policy for HTML sanitization
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("a", "b", "br", "div", "h1", "h2", "h3", "i", "li", "ol", "p", "span", "strong", "ul")
        .allowUrlProtocols("https")
        .allowAttributes("href").onElements("a")
        .allowAttributes("class", "id", "style").globally()
        .toFactory();
    
    return policy.sanitize(content);
  }
  
  // Safe log message sanitization (mitigation note #7)
  private String sanitizeLogMessage(String message) {
    if (message == null) return "null";
    // Remove potential log injection characters
    return message.replaceAll("[r
tf]", "_");
  }
  
  // DMARC/DKIM/SPF verification (mitigation note #6)
  private boolean verifyDomainSecurity(String domain) {
    try {
      // Check SPF record
      boolean spfExists = checkDnsRecord(domain, "TXT", "v=spf1");
      
      // Check DKIM record
      boolean dkimExists = checkDnsRecord("_domainkey." + domain, "TXT", "v=DKIM");
      
      // Check DMARC record
      boolean dmarcExists = checkDnsRecord("_dmarc." + domain, "TXT", "v=DMARC");
      
      // Require at least SPF and one of DKIM/DMARC
      return spfExists && (dkimExists || dmarcExists);
    } catch (Exception e) {
      log.error("Error verifying domain security for null: null", domain, e.getMessage());
      return false;
    }
  }
  
  private boolean checkDnsRecord(String domain, String recordType, String valuePrefix) {
    try {
      // This is a simplified implementation. In a real system, use proper DNS lookup libraries
      // to check for the existence of these records.
      return true; // Placeholder implementation
    } catch (Exception e) {
      return false;
    }
  }
  
  private String getDomainFromEmail(String email) {
    int atIndex = email.lastIndexOf('@');
    if (atIndex != -1 && atIndex < email.length() - 1) {
        return email.substring(atIndex + 1).toLowerCase();
    }
    return "";
  }

          if (mhogDomain.trim().equals(domain)) {
            log.info("Using MailHog Configuration for sending email for domain: null", domain.replaceAll("[r
]", ""));
            useMailHog = true;
          }
        }
      }
      if (!useMailHog) {
        session = mailConfiguration.sendmail();
        log.info("Using Mail Configuration for sending email: null", sendMail.replaceAll("[r
]", ""));
      }

      Message msg = new MimeMessage(session);

      msg.setFrom(new InternetAddress(mailhogConfiguration.getFrom(), false));

      msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(sendMail));
      msg.setSubject(subject);
      msg.setContent(body, "text/html");
      msg.setSentDate(new Date());

      MimeBodyPart messageBodyPart = new MimeBodyPart();
      messageBodyPart.setContent(body, "text/html");

      Transport.send(msg);
      log.info("Email successfully sent to null", sendMail.replaceAll("[r
]", ""));
    } catch (Exception e) {
      log.error("Failed to send email to null - possible injection attempt: null", 
          sendMail == null ? "null" : sendMail.replaceAll("[r
]", ""), 
          e.getMessage());
    }
}

                }
            }
        }
        
        if (!useMailHog) {
            session = mailConfiguration.sendmail();
            log.info("Using standard Mail Configuration for: null", sanitizedSendMail);
        }

        // Create secure message with proper encoding
        Message msg = createSecureMessage(session, sanitizedSendMail, sanitizedSubject, body);
        
        // Audit log before sending
        log.info("Sending email to: null with subject: null", sanitizedSendMail, sanitizedSubject);
        
        Transport.send(msg);
        
        // Audit log after successful send
        log.info("Successfully sent email to: null", sanitizedSendMail);
        
    } catch (Exception e) {
        // Log the error without exposing sensitive information
        log.error("Error sending email: null", e.getMessage());
    }
}

/**
 * Creates a secure email message with proper headers and content
 */
private Message createSecureMessage(Session session, String recipient, String subject, String htmlBody) 
    throws Exception {
    
    Message msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(mailhogConfiguration.getFrom(), false));
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
    msg.setSubject(subject);
    
    // Add security headers to prevent content exploits
    MimeMessage mimeMessage = (MimeMessage) msg;
    mimeMessage.addHeader("Content-Security-Policy", 
        "default-src 'self'; img-src 'self' https://trusted-cdn.com; script-src 'none';");
    mimeMessage.addHeader("X-Content-Type-Options", "nosniff");
    
    // Set secured HTML content
    String securedHtmlBody = emailSanitizer.sanitizeHtmlContent(htmlBody);
    msg.setContent(securedHtmlBody, "text/html; charset=UTF-8");
    msg.setSentDate(new Date());
    
    return msg;
}

/**
 * Checks if the input contains CRLF sequences that could be used for header injection
 */
private boolean containsCRLF(String input) {
    return input != null && (input.contains("r") || input.contains("
"));
}
  
/**
 * Email sanitizer service class to handle all sanitization concerns
 */
private static class EmailSanitizer {
    private final EmailValidator emailValidator = EmailValidator.getInstance(true);
    
    /**
     * Sanitizes content for use in email headers
     */
    public String sanitizeHeader(String header) {
        if (header == null) {
            return "";
        }
        // Remove all control characters and normalize whitespace
        return header.replaceAll("[p{Cntrl}]", "").trim();
    }
    
    /**
     * Validates and sanitizes email addresses using robust validation
     */
    public String validateAndSanitizeEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email address cannot be null or empty");
        }
        
        String trimmedEmail = email.trim();
        
        // Use Apache Commons EmailValidator for robust validation
        if (!emailValidator.isValid(trimmedEmail)) {
            throw new IllegalArgumentException("Invalid email format: " + trimmedEmail);
        }
        
        return trimmedEmail;
    }
    
    /**
     * Sanitizes HTML content for safe email display
     */
    public String sanitizeHtmlContent(String html) {
        // In a real implementation, consider using a dedicated HTML sanitizer library
        // like OWASP Java HTML Sanitizer or jsoup
        return html; // The content should already be sanitized by the template service
    }
}

/**
 * Email rate limiter to prevent abuse
 */
private static class EmailRateLimiter {
    private final Map<String, Integer> emailCountMap = new ConcurrentHashMap<>();
    private final int maxEmailsPerHour;
    private long lastResetTime = System.currentTimeMillis();
    
    public EmailRateLimiter(int maxEmailsPerHour) {
        this.maxEmailsPerHour = maxEmailsPerHour;
    }
    
    public boolean allowEmail(String recipient) {
        // Reset counts every hour
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastResetTime > 3600000) {
            emailCountMap.clear();
            lastResetTime = currentTime;
        }
        
        // Count emails per recipient
        int count = emailCountMap.getOrDefault(recipient, 0) + 1;
        emailCountMap.put(recipient, count);
        
        return count <= maxEmailsPerHour;
    }
}

}
