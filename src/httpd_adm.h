
#ifndef __HTTPD_ADM_H__
#define __HTTPD_ADM_H__

#include <event.h>
#ifdef HAVE_LIBEVENT2
# include <event2/http.h>
#else
# include "evhttp/evhttp_compat.h"
#endif

int
adm_init(void);

void
adm_deinit(void);

void
adm_request(struct evhttp_request *req);

int
adm_is_request(struct evhttp_request *req, char *uri);

#endif /* !__HTTPD_ADM_H__ */
