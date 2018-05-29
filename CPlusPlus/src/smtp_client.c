#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdarg.h>
#include <libgen.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define NONEED_SELECT     1

#define SMTP_MTU          800
#define MAX_EMAIL_LEN     256
#define TEXT_BOUNDARY     "------------03145242DFEEEAFBB1FE425E"

struct SMTP_Private
{
    unsigned char *mail;
    int isLetterFinalized;
    int socketFd;
    int attachmentIdSeed;
    char *mailFrom;
    char *mailTo;
    SSL *ssl;
};

#include "smtp_client.h"

/**
 * Calculate the output size needed to base64-encode x bytes.
 */
#define BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))

static char base64_encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static size_t base64_mod_table[] = {0, 2, 1};

static char *base64_encode(char *encoded_data, size_t out_size, const unsigned char *data, size_t input_length)
{
    size_t output_length;
    size_t i, j;

    output_length = 4 * ((input_length + 2) / 3);
    memset(encoded_data, 0, out_size);
    if(output_length >= out_size)
        return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < base64_mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    return encoded_data;
}


static ssize_t stringCut(const unsigned char *pcSrc, const unsigned char *start, const unsigned char *end, unsigned char *pcDest)
{
    const unsigned char *posStart = NULL;
    const unsigned char *posEnd = NULL;
    ssize_t len;

    if(0 == *pcSrc || NULL == pcDest)
    {
        return -1;
    }

    if(NULL == start)
    {
        posStart = pcSrc;
    }
    else
    {
        posStart = (const unsigned char*)strstr((const char*)pcSrc, (const char*)start);
        if(NULL == posStart)
        {
            return -1;
        }
        /* ignore header */
        posStart++;
    }

    if(NULL == end)
    {
        posEnd = posStart + strlen((const char*)posStart);
    }
    else
    {
        posEnd = (const unsigned char*)strstr((const char*)pcSrc, (const char*)end);
        if(NULL == posEnd)
        {
            return -1;
        }
    }

    len = posEnd - posStart;

    strncpy((char*)pcDest, (const char*)posStart, (size_t)len);

    return len;
}

int smtp_init(SMTP_Client **smtp)
{
    *smtp = (SMTP_Client*)calloc(sizeof(SMTP_Client), 1);
    if(*smtp == NULL)
        return -1;
    (*smtp)->p = calloc(sizeof(struct SMTP_Private), 1);
    (*smtp)->p->mail = NULL;
    (*smtp)->p->isLetterFinalized = 0;
    (*smtp)->p->socketFd = 0;
    (*smtp)->errorString = malloc(10240);
    (*smtp)->p->attachmentIdSeed = 1000 + rand() % 99999;
    (*smtp)->debugPrint = 0;
    (*smtp)->debugStream = stdout;
    (*smtp)->p->mailFrom = malloc(MAX_EMAIL_LEN);
    memset((*smtp)->p->mailFrom, 0, MAX_EMAIL_LEN);
    (*smtp)->p->mailTo = malloc(MAX_EMAIL_LEN);
    memset((*smtp)->p->mailTo, 0, MAX_EMAIL_LEN);

    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();

    return 0;
}

int smtp_free(SMTP_Client **smtp)
{
    if(smtp && *smtp)
    {
        if((*smtp)->p->ssl)
            SSL_free((*smtp)->p->ssl);
        (*smtp)->p->ssl = NULL;
        if((*smtp)->p->socketFd)
            close((*smtp)->p->socketFd);
        (*smtp)->p->socketFd = 0;
        if((*smtp)->p->mail)
            free((*smtp)->p->mail);
        if((*smtp)->errorString)
            free((*smtp)->errorString);
        if((*smtp)->p->mailFrom)
            free((*smtp)->p->mailFrom);
        if((*smtp)->p->mailTo)
            free((*smtp)->p->mailTo);
        if((*smtp)->p)
            free((*smtp)->p);
        free(*smtp);
        *smtp = NULL;

        ERR_remove_state(0);
        ERR_free_strings();
        EVP_cleanup();
        sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
        CRYPTO_cleanup_all_ex_data();
    }
    return 0;
}

static void smtp_printError(SMTP_Client *smtp, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vsnprintf(smtp->errorString, 10240, fmt, va);
}

static void smtp_printSssError(SMTP_Client *smtp, const char *header)
{
    size_t err;
    char *errStr = NULL;
    size_t errLen = 0;

    if(header)
    {
        errStr = strdup(header);
        errLen = strlen(header);
    }

    while((err = ERR_get_error()) != 0)
    {
        char *str = ERR_error_string(err, 0);
        if(!str)
            break;
        if(!errStr)
        {
            errStr = strdup(str);
            errLen = strlen(str);
        }
        else
        {
            size_t len = strlen(str);
            errStr = realloc(errStr, errLen + len + 1);
            strcat(errStr, "\n");
            strcat(errStr, str);
        }
    }

    if(errStr)
    {
        smtp_printError(smtp, errStr);
        free(errStr);
    }
}

int smtp_connect(SMTP_Client *smtp, const char *smtpHostName, const unsigned short smtpPort, int security)
{
    struct sockaddr_in smtpAddr;
    struct hostent *host = NULL;

    smtp->p->socketFd = -1;
    memset(&smtpAddr, 0, sizeof(smtpAddr));

    if(NULL == (host = gethostbyname((const char*)smtpHostName)))
    {
        smtp_printError(smtp, "Can't resolve hostname %s!", smtpHostName);
        return -1;
    }

    memset(&smtpAddr, 0, sizeof(smtpAddr));
    smtpAddr.sin_family = AF_INET;
    smtpAddr.sin_port = htons(smtpPort);
    smtpAddr.sin_addr = *((struct in_addr *)host->h_addr);

    smtp->p->socketFd = socket(PF_INET, SOCK_STREAM, 0);
    if(0 > smtp->p->socketFd)
    {
        smtp_printError(smtp, "Can't Initialize socket!");
        smtp->p->socketFd = 0;
        return -1;
    }

    if(0 > connect(smtp->p->socketFd, (struct sockaddr *)&smtpAddr, sizeof(struct sockaddr)))
    {
        close(smtp->p->socketFd);
        smtp->p->socketFd = 0;
        smtp_printError(smtp, "Can't connect to host %s:%u!", smtpHostName, smtpPort);
        return -1;
    }

    if(security == SMTP_SSL)
    {
        const SSL_METHOD *meth = NULL;
        SSL_CTX *ctx = NULL;
        int sock;

        meth = TLSv1_2_client_method();
        ctx = SSL_CTX_new (meth);
        smtp->p->ssl = SSL_new (ctx);
        if (!smtp->p->ssl) {
            smtp_printSssError(smtp, "Error of SSL connection creation!\n");
            close(smtp->p->socketFd);
            return -1;
        }
        sock = SSL_get_fd(smtp->p->ssl);
        SSL_set_fd(smtp->p->ssl, smtp->p->socketFd);
        if(SSL_connect(smtp->p->ssl) < 0)
        {
            smtp_printSssError(smtp, "Error creating SSL connection!\n");
            SSL_free(smtp->p->ssl);
            smtp->p->ssl = NULL;
            close(smtp->p->socketFd);
            return -1;
        }
    }
    else if(security == SMTP_TSL)
    {
        smtp_printSssError(smtp, "STARTTSL support is not implemented in this library. Yet!\n");
        close(smtp->p->socketFd);
        smtp->p->socketFd = 0;
        return -1;
    }

    return 0;
}

int smtp_close(SMTP_Client *smtp)
{
    int ret = close(smtp->p->socketFd);
    smtp->p->socketFd = 0;
    return ret;
}

static int smtp_sslRecv(SMTP_Client *smtp, unsigned char* inbuf, size_t buf_size)
{
    int len;
    do {
        len = SSL_read(smtp->p->ssl, inbuf, (int)buf_size);
        inbuf[len] = 0;
    } while (len > (int)buf_size);

    if (len < 0) {
        int err = SSL_get_error(smtp->p->ssl, len);
        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }

    return 0;
}

static int smtp_sslSend(SMTP_Client *smtp, const unsigned char* outbuf, size_t buf_size)
{
    int len = SSL_write(smtp->p->ssl, outbuf, (int)buf_size);
    if (len < 0) {
        int err = SSL_get_error(smtp->p->ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
    return 0;
}

static ssize_t socketRead(int socketFd, unsigned char *readData, size_t readLen)
{
    return recv(socketFd, (char*)readData, readLen, 0);
}

static ssize_t socketWrite(int socketFd, const unsigned char *writeData, size_t writeLen)
{
    return send(socketFd, writeData, writeLen, 0);
}

static void removeEndlEnding(char *str);

static ssize_t smtp_sendData_real(const char *file, int line, SMTP_Client *smtp, const unsigned char *data, size_t size)
{
    if(smtp->debugPrint)
    {
        char *duped = strdup((const char*)data);
        removeEndlEnding(duped);
        fprintf(smtp->debugStream, "[%s][%d] OUT>>: %s\n", file, line, duped);
        free(duped);
    }
    if(smtp->p->ssl)
        return smtp_sslSend(smtp, data, size);
    else
        return socketWrite(smtp->p->socketFd, data, size);
}

static ssize_t smtp_recvData_real(const char *file, int line, SMTP_Client *smtp, unsigned char *data, size_t size)
{
    ssize_t ret = 0;
    if(smtp->p->ssl)
        ret = smtp_sslRecv(smtp, data, size);
    else
        ret = socketRead(smtp->p->socketFd, data, size);
    if(smtp->debugPrint)
    {
        char *duped = strdup((const char*)data);
        removeEndlEnding(duped);
        fprintf(smtp->debugStream, "[%s][%d] IN <<: %s\n", file, line, duped);
        free(duped);
    }
    return ret;
}

#define smtp_sendData(smtp, data, size) smtp_sendData_real(__FILE__, __LINE__, smtp, data, size);
#define smtp_recvData(smtp, data, size) smtp_recvData_real(__FILE__, __LINE__, smtp, data, size);

/*
 * You can find more detail in here.
 * http://www.ietf.org/rfc/rfc821.txt
 */
static int recvStatus(SMTP_Client *smtp, const unsigned char *recvString)
{
    char statusStr[4] = {0};
    int reply;

    memset(statusStr, 0, sizeof(statusStr));
    strncpy(statusStr, (const char*)recvString, 3);
    reply = atoi(statusStr);

    if(smtp->debugPrint)
        fprintf(smtp->debugStream, "[%s][%d] status = %d\n", __FILE__, __LINE__, atoi(statusStr));

    switch(reply)
    {
    case 250: case 235: case 354: case 334: case 221: break;
    default:
        if(smtp->debugPrint)
        {
            fprintf(smtp->debugStream, "Received status is an error!");
        }
        return -1;
    }

    return 0;
}

static char *strdup_as_base64(const char *input)
{
    char *base64Attach = NULL;
    size_t src_len = strlen(input);
    size_t base64_len = BASE64_SIZE(strlen(input));

    base64Attach = calloc(base64_len, 1);
    if(base64Attach == NULL)
        return NULL;
    base64_encode(base64Attach, base64_len, (const unsigned char*)input, src_len);
    return base64Attach;
}

static void removeEndlEnding(char *str)
{
    if(str == NULL || *str == '\0')
        return;
    while(*str != '\0')
        str++;
    str--;
    if(*str == '\n')
        *str = '\0';
}


int smtp_login(SMTP_Client *smtp, const char *smtpLogin, const char *smtpPasswd)
{
    size_t outSize = 0;
    char readData[SMTP_MTU];
    char writeData[SMTP_MTU];
    char userName[MAX_EMAIL_LEN];
    char userPasswd[MAX_EMAIL_LEN];

    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);

    /* Send: EHLO */
    smtp_sendData(smtp, (const unsigned char*)"EHLO Here\r\n", strlen("EHLO Here\r\n"));

    /* Recv: EHLO */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: AUTH LOGIN */
    smtp_sendData(smtp, (const unsigned char*)"AUTH LOGIN\r\n", strlen("AUTH LOGIN\r\n"));

    /* Recv: AUTH LOGIN */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: username */
    memset(&userName, 0, MAX_EMAIL_LEN);
    memset(&writeData, 0, SMTP_MTU);
    strncpy(userName, smtpLogin, MAX_EMAIL_LEN - 1);

    outSize = BASE64_SIZE(strlen(userName));
    base64_encode(writeData, outSize, (unsigned char*)userName, strlen(userName));
    strcat(writeData, "\r\n");
    smtp_sendData(smtp, (const unsigned char*)writeData, strlen(writeData));

    /* Recv: username */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: passwd */
    memset(&userPasswd, 0, MAX_EMAIL_LEN);
    strcpy(userPasswd, smtpPasswd);
    memset(&writeData, 0, SMTP_MTU);
    outSize = BASE64_SIZE(strlen(userPasswd));
    base64_encode(writeData, outSize, (unsigned char*)userPasswd, strlen(userPasswd));
    strcat(writeData, "\r\n");
    smtp_sendData(smtp, (const unsigned char*)writeData, strlen(writeData));

    /* Recv: passwd */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (const unsigned char*)readData) < 0)
        return -1;
    return 0;
}

int smtp_sendLetter(SMTP_Client *smtp)
{
    char readData[SMTP_MTU] = {0};
    char writeData[SMTP_MTU] = {0};

    const unsigned char *textMail = smtp->p->mail;
    size_t textLen = strlen((char*)smtp->p->mail);

    if(smtp->p->isLetterFinalized == 0)
    {
        /* Fianlize letter whet it is not finalized! */
        smtp_endLetter(smtp);
        textLen = strlen((char*)smtp->p->mail);
    }

    /* Send: MAIL FROM */
    memset(&writeData, 0, SMTP_MTU);
    sprintf(writeData, "MAIL FROM:<%s>\r\n", smtp->p->mailFrom);
    smtp_sendData(smtp, (const unsigned char*)writeData, strlen(writeData));

    /* Recv: MAIL FROM */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: RCPT TO */
    memset(&writeData, 0, SMTP_MTU);
    sprintf(writeData, "RCPT TO:<%s>\r\n", smtp->p->mailTo);
    smtp_sendData(smtp, (const unsigned char*)writeData, strlen(writeData));

    /* Recv: RCPT TO */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: DATA */
    memset(&writeData, 0, SMTP_MTU);
    smtp_sendData(smtp, (const unsigned char*)"DATA\r\n", strlen("DATA\r\n"));

    /* Recv: DATA */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: MAIL TEXT */
    smtp_sendData(smtp, textMail, textLen);

    /* Recv: MAIL TEXT */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    /* Send: QUIT */
    memset(&writeData, 0, SMTP_MTU);
    smtp_sendData(smtp, (unsigned char*)"QUIT\r\n", strlen("QUIT\r\n"));

    /* Recv: QUIT */
    memset(&readData, 0, SMTP_MTU);
    smtp_recvData(smtp, (unsigned char*)readData, SMTP_MTU);
    if(recvStatus(smtp, (unsigned char*)readData) < 0)
        return -1;

    return 0;
}

/* Initialize new letter */
ssize_t smtp_createLetter(SMTP_Client *smtp,
                          int textFormat,
                          const char *fromName,
                          const char *fromMail,
                          const char *toName,
                          const char *toMail,
                          const char *mailSubject,  const char *mailBody)
{
    size_t mailTextLen = 0;
    char fromName_g[MAX_EMAIL_LEN];
    char toName_g[MAX_EMAIL_LEN];
    char *textOfLetter = NULL;
    char *from_base64;
    char *to_base64;
    char *subject_base64;

    if(smtp->p->mail)
        free(smtp->p->mail);
    smtp->p->mail = calloc(1, 1);
    smtp->p->isLetterFinalized = 0;

    if(fromMail == NULL)
    {
        smtp_printError(smtp, "[%s][%s]: You must specifiy FROM email address!", __FILE__, __LINE__);
        return -1;
    }

    if(toMail == NULL)
    {
        smtp_printError(smtp, "[%s][%s]: You must specifiy TO email address!", __FILE__, __LINE__);
        return -1;
    }


    mailTextLen = strlen(fromMail) + strlen(toMail) + strlen(mailSubject) + strlen(mailBody) + 500;

    textOfLetter = calloc(mailTextLen, 1);
    if(NULL == textOfLetter)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        return -1;
    }

    memset(&fromName_g, 0, MAX_EMAIL_LEN);
    strncpy(smtp->p->mailFrom, fromMail, MAX_EMAIL_LEN);
    if(fromName)
        strncpy(fromName_g, fromName, MAX_EMAIL_LEN);
    else
        stringCut((const unsigned char*)fromMail, NULL, (const unsigned char*)"@", (unsigned char*)fromName_g);

    memset(&toName_g, 0, MAX_EMAIL_LEN);
    strncpy(smtp->p->mailTo, toMail, MAX_EMAIL_LEN);
    if(toName)
        strncpy(toName_g, toName, MAX_EMAIL_LEN);
    else
        stringCut((const unsigned char*)toMail, NULL, (const unsigned char*)"@", (unsigned char*)toName_g);

    from_base64     = strdup_as_base64(fromName);
    to_base64       = strdup_as_base64(toName);
    subject_base64  = strdup_as_base64((const char*)mailSubject);

    snprintf(textOfLetter, mailTextLen,
             "From: \"=?UTF-8?B?%s?=\"<%s>\r\n"
             "To: \"=?UTF-8?B?%s?=\"<%s>\r\n"
             "Subject: =?UTF-8?B?%s?=\r\n"

             "MIME-Version:1.0\r\n"
             "X-Mailer: Wohlstand's libSMTPClient v %d.%d.%d\r\n"
             "Content-Type:multipart/mixed;\n boundary=\"%s\"\r\n\r\n"

             "This is a multi-part message in MIME format.\r\n"
             "--%s\r\n"
             "Content-Type: text/%s; charset=\"UTF-8\"\r\n"
             "Content-Transfer-Encoding: 8bit\r\n"

             "\r\n%s\r\n\r\n\r\n",

             from_base64, fromMail,
             to_base64, toMail,
             subject_base64,
             SMTP_CLIENT_VERSION_MAJOR, SMTP_CLIENT_VERSION_MINOR, SMTP_CLIENT_VERSION_PATCH,
             TEXT_BOUNDARY,
             TEXT_BOUNDARY,
             (textFormat == SMTP_TextPlain ? "plain" :
              textFormat == SMTP_TextHTML ? "html" :
              "plain"),
             mailBody);

    free(from_base64);
    free(to_base64);
    free(subject_base64);

    smtp->p->mail = realloc(smtp->p->mail, strlen((const char*)smtp->p->mail) + strlen(textOfLetter) + 1);
    if(NULL == smtp->p->mail)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        return -1;
    }

    strcat((char*)smtp->p->mail, textOfLetter);

    free(textOfLetter);
    return (ssize_t)(mailTextLen - strlen((const char*)smtp->p->mail));
}

/* static attachmemt size */
ssize_t smtp_attachFile(SMTP_Client *smtp, const char *filePath)
{
    FILE *fp = NULL;
    ssize_t fileSize, base64Size, headerSize, len;
    char *fileBaseName = NULL;
    char *attach = NULL, *base64Attach = NULL, *attachHeader = NULL;
    char fileName[MAX_EMAIL_LEN] = {0};
    const char *contentType     = "Content-Type: application/octet-stream";
    const char *contentEncode   = "Content-Transfer-Encoding: base64";
    const char *contentDes      = "Content-Disposition: attachment";

    if(smtp->p->isLetterFinalized)
    {
        smtp_printError(smtp, "Can't attach file to finalized letter!");
        return -1;
    }

    fp = fopen(filePath, "rb");
    if(fp == NULL)
    {
        smtp_printError(smtp, "Can't open attachment file %s!", filePath);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    if(0 > fileSize)
    {
        smtp_printError(smtp, "Can't get size of the file %s!", filePath);
        return -1;
    }

    rewind(fp);

    attach = (char*)calloc((size_t)fileSize, 1);
    if(NULL == attach)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        return -1;
    }

    headerSize = (ssize_t)(strlen((const char*)contentType) +
                           strlen(contentEncode) +
                           strlen(contentDes) +
                           (strlen(TEXT_BOUNDARY) * 2) +
                           (strlen(fileName) * 2) +
                           200);
    attachHeader = (char*)calloc((size_t)headerSize, 1);
    if(NULL == attach)
    {
        smtp_printError(smtp, "Out of memory");
        return -1;
    }

    /* attachment header */
    strcpy(fileName, filePath);
    fileBaseName = basename(fileName);
    strcpy(fileName, fileBaseName);

    sprintf(attachHeader,
            "--%s\r\n"
            "%s;\n name=\"%s\"\r\n"
            "%s\r\n"
            "X-Attachment-Id: %d\r\n"
            "%s;\n filename=\"%s\"\r\n\r\n",
            TEXT_BOUNDARY,
            contentType,
            fileName,
            contentEncode,
            (smtp->p->attachmentIdSeed)++,
            contentDes,
            fileName);

    base64Size = BASE64_SIZE(fileSize);
    base64Attach = (char*)calloc((size_t)base64Size, 1);
    if(NULL == base64Attach)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        return -1;
    }

    len = (ssize_t)fread(attach, sizeof(char), (size_t)fileSize, fp);

    if(smtp->debugPrint)
    {
        fprintf(smtp->debugStream, "[%s][%d] %s size = %lu, base64Size = %lu \r\n",
                __FILE__, __LINE__,
                filePath, fileSize, base64Size);
    }

    /* attachment transform to base64 */
    base64_encode(base64Attach, (size_t)base64Size, (const unsigned char*)attach, (size_t)fileSize);

    free(attach);

    smtp->p->mail = realloc(smtp->p->mail, strlen((const char*)smtp->p->mail) + (size_t)headerSize + (size_t)base64Size + 1);
    if(NULL == smtp->p->mail)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        /* what should I do? */
        return -1;
    }

    strcat((char*)smtp->p->mail, attachHeader);
    strcat((char*)smtp->p->mail, base64Attach);
    strcat((char*)smtp->p->mail, "\r\n");

    free(attachHeader);
    free(base64Attach);

    return fileSize;
}

ssize_t smtp_endLetter(SMTP_Client *smtp)
{
    char bodyEnd[200] = {0};
    ssize_t len;

    if(smtp->p->isLetterFinalized)
    {
        smtp_printError(smtp, "Letter is already finalized!");
        return -1;
    }

    memset(bodyEnd, 0, sizeof(bodyEnd));
    sprintf(bodyEnd, "--%s--\r\n\r\n.\r\n", TEXT_BOUNDARY);

    len = (ssize_t)strlen(bodyEnd);

    smtp->p->mail = realloc(smtp->p->mail, strlen((const char*)smtp->p->mail) + (size_t)len + 1);
    if(NULL == smtp->p->mail)
    {
        smtp_printError(smtp, "[%s][%s]: Out of memory!", __FILE__, __LINE__);
        return -1;
    }

    strcat((char*)smtp->p->mail, bodyEnd);

    smtp->p->isLetterFinalized = 1;

    return 0;
}
