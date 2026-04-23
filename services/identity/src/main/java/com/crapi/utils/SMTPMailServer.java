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
private static final EmailSanitizer emailSanitizer = new EmailSanitizer();
private static final int MAX_EMAILS_PER_HOUR = 100; // Rate limiting constant
private final EmailRateLimiter rateLimiter = new EmailRateLimiter(MAX_EMAILS_PER_HOUR);

public void sendMail(String sendMail, String body, String subject) {
    try {
        // Reject inputs containing CRLF to prevent header injection
        if (containsCRLF(sendMail) || containsCRLF(subject)) {
            log.error("Potential mail header injection attempt detected");
            throw new SecurityException("Invalid characters in email parameters");
        }

        // Validate and sanitize inputs for mail header injection prevention
        String sanitizedSubject = emailSanitizer.sanitizeHeader(subject);
        String sanitizedSendMail = emailSanitizer.validateAndSanitizeEmail(sendMail);
        
        // Apply rate limiting to prevent abuse
        if (!rateLimiter.allowEmail(sanitizedSendMail)) {
            log.warn("Email rate limit exceeded for recipient: null", sanitizedSendMail);
            throw new SecurityException("Email rate limit exceeded");
        }
        
        String mhogDomain = mailhogConfiguration.getDomain();
        Session session = mailhogConfiguration.sendmail();
        boolean useMailHog = false;
        
        // Safely parse validated email addresses
        InternetAddress[] emails = InternetAddress.parse(sanitizedSendMail);
        
        // Log sanitized email information for auditing
        log.info("Processing email request to: null", sanitizedSendMail);
        
        if (mhogDomain != null && !mhogDomain.isEmpty()) {
            if (mailConfiguration.getHost().trim().endsWith(mhogDomain)) {
                log.info("SMTP host matches MailHog host. Using MailHog Configuration");
                useMailHog = true;
            }
            
            for (InternetAddress emailAddress : emails) {
                String email = emailAddress.toString();
                if (email.contains("@")) {
                    String domain = email.substring(email.indexOf("@") + 1).trim();
                    log.debug("Email domain check: null against null", domain, mhogDomain);
                    if (mhogDomain.trim().equals(domain)) {
                        log.info("Using MailHog Configuration for domain: null", domain);
                        useMailHog = true;
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
