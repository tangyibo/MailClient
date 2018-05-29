#ifndef SMTPC_H
#define SMTPC_H

#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SMTP_CLIENT_VERSION_MAJOR 1
#define SMTP_CLIENT_VERSION_MINOR 0
#define SMTP_CLIENT_VERSION_PATCH 0

struct SMTP_Private;

typedef struct
{
    /*! Internal private variables*/
    struct SMTP_Private *p;
    /*! Turn on debug print*/
    int debugPrint;
    /*! Output stream (file, stdout or stderr on your choice)*/
    FILE *debugStream;
    /*! Last error string*/
    char *errorString;
} SMTP_Client;

typedef enum
{
    /*! Insecure RAW SMTP*/
    SMTP_NONSECURE,
    /*! TSL SMTP [WIP]*/
    SMTP_TSL,
    /*! SSL-SMTP*/
    SMTP_SSL
} SMTP_Security;

typedef enum
{
    /*! Plain text */
    SMTP_TextPlain,
    /*! HMTL */
    SMTP_TextHTML
} SMTP_BodyFormat;

/**
 * @brief Initialize SMTP instance
 * @param smtp Pointer to pointer of SMTP instance
 * @return 0 on success, -1 on any error
 */
int smtp_init(SMTP_Client **smtp);
/**
 * @brief Clear SMTP instance and close any connections
 * @param smtp Pointer to pointer of SMTP instance
 * @return 0 on success, -1 on any error
 */
int smtp_free(SMTP_Client **smtp);

/**
 * @brief Connect to SMTP server
 * @param smtp Pointer to SMTP instance
 * @param smtpHostName Server name or IP address
 * @param smtpPort Port of SMTP server
 * @param security Connection type: non-encrypted or SSL
 * @return 0 on success, -1 on any error
 */
int smtp_connect(SMTP_Client *smtp, const char *smtpHostName, const unsigned short smtpPort, int security);

/**
 * @brief smtp_close Close SMTP instance
 * @param smtp Pointer to SMTP instance
 * @return 0 on success, -1 on any error
 */
int smtp_close(SMTP_Client *smtp);


/**
 * @brief Create the letter
 * @param smtp Pointer to SMTP instance
 * @param textFormat Format of the body text: plain text or HTML-formatted
 * @param fromName Name of sender
 * @param fromMail E-Mail address of sender
 * @param toName Name of receipient
 * @param toMail E-Mail address of receipient
 * @param mailSubject Subject of the letter
 * @param mailBody Body of the letter
 * @return 0 on success, -1 on any error
 */
ssize_t smtp_createLetter(SMTP_Client *smtp,
                          int textFormat,
                          const char *fromName, const char *fromMail,
                          const char *toName,   const char *toMail,
                          const char *mailSubject, const char *mailBody);


/**
 * @brief Attach a file by path
 * @param smtp Pointer to SMTP instance
 * @param filePath Path to file to attach
 * @return 0 on success, -1 on any error
 */
ssize_t smtp_attachFile(SMTP_Client *smtp, const char *filePath);

/**
 * @brief Finalize letter (Must be, or letter will NOT be accepted by SMTP server!)
 * @param smtp Pointer to SMTP instance
 * @return 0 on success, -1 on any error
 */
ssize_t smtp_endLetter(SMTP_Client *smtp);


/**
 * @brief Authentificate SMTP connection
 * @param smtp Pointer to SMTP instance
 * @param smtpLogin Login
 * @param smtpPasswd Password
 * @return 0 on success, -1 on any error
 */
int smtp_login(SMTP_Client *smtp, const char *smtpLogin, const char *smtpPasswd);

/**
 * @brief Send letter
 * @param smtp Pointer to SMTP instance
 * @return 0 on success, -1 on any error
 */
int smtp_sendLetter(SMTP_Client *smtp);

#ifdef __cplusplus
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <assert.h>
using std::string;
using std::vector;

/*
 * @brief Mail Sender class wraper
 */
class MailSender
{
public:

    /**
     * @brief  construct function
     * @param host domain or ip address ,for example: "smtp.sina.com"
     * @param user username which for login
     * @param passwd password which for login
     * @param ssl whether use SSL or not
     */
    MailSender ( const string &host, const string &user, const string &passwd, bool ssl = false )
    : m_smtp ( NULL ), m_use_ssl ( ssl ), m_host ( host ), m_user ( user ), m_passwd ( passwd ), m_mailto ( "" )
    {
        assert ( 0 == smtp_init ( &m_smtp ) );
    }

    /**
     * @brief  deconstruct function
     */
    ~MailSender ( )
    {
        smtp_free ( &m_smtp );
    }

    /**
     * @brief  set mail subject
     * @param subject  the subject 
     */
    void SetSubject ( const string &subject )
    {
        m_subject = subject;
    }

    /**
     * @brief  set mail content
     * @param content  the content 
     */
    void SetContent ( const string &content )
    {
        m_content = content;
    }

    /**
     * @brief  set mail to address
     * @param mailto  mail to address
     */
    void SetMailTo ( const string &mailto )
    {
        m_mailto = mailto;
    }

    /**
     * @brief  set attach file
     * @param filename   attachment filename
     */
    void SetAttachFile ( const string &filename )
    {
        m_attachs.push_back ( filename );
    }

    /**
     * @brief  real send mail
     */
    int SendMail ( )
    {
        int ret = pre_prepare ( );
        if ( ret < 0 )
        {
            return ret;
        }

        int security = SMTP_NONSECURE;
        if ( m_use_ssl )
        {
            security = SMTP_SSL;
        }

        if ( smtp_connect ( m_smtp, m_host.c_str ( ), 25, security ) < 0 )
        {
            fprintf ( stderr, "connect FAILED ... [%s]\n", m_smtp->errorString );
            return -1;
        }

        ret = smtp_login ( m_smtp, m_user.c_str ( ), m_passwd.c_str ( ) );
        if ( ret < 0 )
        {
            fprintf ( stderr, "auth FAILED ... [%s]\r\n", m_smtp->errorString );
            return -1;
        }

        ret = smtp_sendLetter ( m_smtp );
        if ( ret < 0 )
        {
            fprintf ( stderr, "send FAIL ... [%s]\n", m_smtp->errorString );
            return -1;
        }

        return 0;
    }

    /**
     * @brief  return last error message
     */
    string LastErrorMessage()
    {
        return string(m_smtp->errorString);
    }
    
protected:

    int pre_prepare()
    {
        int ret = smtp_createLetter(m_smtp,
                SMTP_TextHTML,
                m_user.c_str(), m_user.c_str(),
                m_mailto.c_str(), m_mailto.c_str(),
                m_subject.c_str(), m_content.c_str());

        if (ret >= 0)
        {
            for (vector<string>::const_iterator it = m_attachs.begin(); it != m_attachs.end() && ret >= 0; ++it)
            {
                ret = smtp_attachFile(m_smtp, (*it).c_str());
            }
        }

        if (ret >= 0)
        {
            ret = smtp_endLetter(m_smtp);
        }

        if (ret < 0)
        {
            fprintf(stderr, "prepare FAILED ... [%s]\n", m_smtp->errorString);
            return -1;
        }

	return ret;
    }

private:
    SMTP_Client *m_smtp;
    bool m_use_ssl;
    string m_host;
    string m_user;
    string m_passwd;
    string m_subject;
    string m_content;
    string m_mailto;
    vector<string> m_attachs;
};

#endif

#endif /*SMTPC_H*/
