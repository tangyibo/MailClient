#include "smtp_client.h"

int main(int argc,char *argv[])
{
    const char *host     = "smtp.sina.com";
    const char *user      = "xxxx@sina.com";
    const char *passwd   = "xxxx";
    const char *mailto   = "xxxx@126.com";

    MailSender ms(host,user,passwd);
    ms.SetSubject("title_test");
    ms.SetContent("content_test");
    ms.SetMailTo(mailto);
    ms.SetAttachFile("./files/foxy.png");
    ms.SetAttachFile("./files/Jazz_walts.mid");
    ms.SendMail();
            
    return 0;
}
