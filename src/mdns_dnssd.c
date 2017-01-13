/*
 * Avahi mDNS backend, with libevent polling
 *
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
 *
 * Pieces coming from mt-daapd:
 * Copyright (C) 2005 Sebastian Dr�ge <slomo@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

#ifdef HAVE_LIBEVENT2
# include <event2/event.h>
#else
# include <event.h>
#endif

#define _DNS_SD_LIBDISPATCH 0
#include <dns_sd.h>

// Hack for FreeBSD, don't want to bother with sysconf()
#ifndef HOST_NAME_MAX
# include <limits.h>
# define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#include "logger.h"
#include "mdns.h"

#define MDNS_WANT_V4    (1 << 0)
#define MDNS_WANT_V4LL  (1 << 1)
#define MDNS_WANT_V6    (1 << 2)
#define MDNS_WANT_V6LL  (1 << 3)

#define MDNS_WANT_DEFAULT (MDNS_WANT_V4 | MDNS_WANT_V6 | MDNS_WANT_V6LL)

/* Main event base, from main.c */
extern struct event_base *evbase_main;

static DNSServiceRef sdref_main;
static DNSRecordRef rref_main;

struct mdns_service {
	DNSServiceRef sdref;
	char *name;
	char *type;
	TXTRecordRef txtRecord;
	struct event *ev;
	struct mdns_service *next;
};

static struct mdns_service *services = NULL;

/* Avahi client callbacks & helpers */

struct mdns_browser
{
  DNSServiceRef sdref;
  char *type;
  mdns_browse_cb cb;
  int flags;
  struct event *ev;
  struct mdns_browser *next;
};

static struct mdns_browser *browser_list = NULL;

struct mdns_resolver
{
  DNSServiceRef sdref;
  char *name;
  char *type;
  char *domain;
  struct mdns_browser *mb;
  struct event *ev;
  struct mdns_resolver *next;
};

struct mdns_addr_lookup {
  DNSServiceRef sdref;
  char *name;
  char *type;
  char *domain;
  u_int16_t port;
  struct keyval txt_kv;
  struct mdns_browser *mb;
  struct event *ev;
};

#define IPV4LL_NETWORK 0xA9FE0000
#define IPV4LL_NETMASK 0xFFFF0000
#define IPV6LL_NETWORK 0xFE80
#define IPV6LL_NETMASK 0xFFC0

static int
is_v4ll(struct in_addr *addr)
{
  return ((ntohl(addr->s_addr) & IPV4LL_NETMASK) == IPV4LL_NETWORK);
}

static int
is_v6ll(struct in6_addr *addr)
{
  return ((((addr->s6_addr[0] << 8) | addr->s6_addr[1]) & IPV6LL_NETMASK) == IPV6LL_NETWORK);
}

/* mDNS interface - to be called only from the main thread */

int
mdns_init(void)
{
  DNSServiceErrorType err;

  DPRINTF(E_DBG, L_MDNS, "Initializing DNS-SD mDNS\n");

  services = NULL;
  browser_list = NULL;

  err = DNSServiceCreateConnection(&sdref_main);
  if (err != kDNSServiceErr_NoError)
    return -1;

  return 0;
}

void
mdns_deinit(void)
{
  struct mdns_service *s;
  struct mdns_browser *mb;

  for(s = services; services; s = services)
    {
      services = s->next;

      /*free(s->txtRecord);*/
      event_del(s->ev);
      #ifdef HAVE_LIBEVENT2
        event_free(s->ev);
      #else
        free(s->ev);
      #endif
      free(s->name);
      free(s->type);
      TXTRecordDeallocate(&(s->txtRecord));
      DNSServiceRefDeallocate(s->sdref);
      free(s);
    }

  for (mb = browser_list; browser_list; mb = browser_list)
    {
      browser_list = mb->next;

      event_del(mb->ev);
      #ifdef HAVE_LIBEVENT2
        event_free(mb->ev);
      #else
        free(mb->ev);
      #endif
      DNSServiceRefDeallocate(mb->sdref);
      free(mb->type);
      free(mb);
    }

  DNSServiceRefDeallocate(sdref_main);
}

void ev_dnssd_cb(evutil_socket_t fd, short flags, void * data) {
  DNSServiceProcessResult(*(DNSServiceRef *)data);
}

static void
register_callback(DNSServiceRef sdRef, DNSServiceFlags flags,
        DNSServiceErrorType errorCode, const char *name,
        const char *regtype, const char *domain, void *context ) {

  switch (errorCode) {
    case kDNSServiceErr_NoError:
      DPRINTF(E_DBG, L_MDNS, "Successfully added mDNS services\n");
      break;

    case kDNSServiceErr_NameConflict:
      DPRINTF(E_DBG, L_MDNS, "Name collision - automatically assigning new name\n");
      break;

    case kDNSServiceErr_NoMemory:
      DPRINTF(E_DBG, L_MDNS, "Out of memory registering service %s\n", name);
      break;

    default:
      DPRINTF(E_DBG, L_MDNS, "Unspecified error registering service %s\n", name);
	}
}

int
mdns_register(char *name, char *type, int port, char **txt)
{
  struct mdns_service *s;
  DNSServiceErrorType err;
  DNSServiceFlags flags = 0;
  //uint16_t txtLen;
  int i;
  int fd;
  char *eq;

  DPRINTF(E_DBG, L_MDNS, "Adding mDNS service %s/%s\n", name, type);

  s = (struct mdns_service *) malloc(sizeof(struct mdns_service));
  if (!s)
    return -1;

  s->name = strdup(name);
  if (!(s->name))
    {
      free(s);
      return -1;
    }

  s->type = strdup(type);
  if (!(s->type))
    {
      free(s->name);
      free(s);
      return -1;
    }

 /*
    txtLen = 0;
    for (i = 0; txt[i]; i++)
      {
        txtLen += strlen(txt[i]) + 1;
      }
*/

  TXTRecordCreate(&(s->txtRecord), 0, NULL);

  for (i = 0; txt[i]; i++)
    {
      if ((eq = strchr(txt[i], '=')))
        {
          *eq = '\0';
          eq++;
          err = TXTRecordSetValue(&(s->txtRecord), txt[i], strlen(eq) * sizeof(char), eq);
          *(--eq) = '=';
          if (err!=kDNSServiceErr_NoError)
            {
              TXTRecordDeallocate(&(s->txtRecord));
              free(s);
              return -1;
            }
        }
    }

  flags = kDNSServiceFlagsShareConnection;
  s->sdref = sdref_main;
  err = DNSServiceRegister(&(s->sdref), flags, 0,
          s->name, s->type, NULL, NULL, htons(port),
          TXTRecordGetLength(&(s->txtRecord)), TXTRecordGetBytesPtr(&(s->txtRecord)),
          register_callback, NULL);

  if (err != kDNSServiceErr_NoError)
    {
      DPRINTF(E_LOG, L_MDNS, "Error registering service %s\n", name);
      goto register_error;
    }

  fd = DNSServiceRefSockFD(s->sdref);
#ifdef HAVE_LIBEVENT2
  s->ev = event_new(evbase_main, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &s->sdref);
  if (!s->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Could not make new event in mdns_register\n");
      DNSServiceRefDeallocate(s->sdref);
      goto register_error;
    }
#else
  s->ev = (struct event *)malloc(sizeof(struct event));
  if (!s->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory in mdns_register\n");
      DNSServiceRefDeallocate(s->sdref);
      goto register_error;
    }

  event_set(s->ev, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &s->sdref);
  event_base_set(evbase_main, s->ev);
#endif

  return event_add(s->ev, NULL);

  s->next = services;
  services = s;

  return 0;

 register_error:
  TXTRecordDeallocate(&(s->txtRecord));
  free(s->name);
  free(s->type);
  free(s);

  return -1;
}

static void cname_callback(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, void *context)
{
  switch (errorCode) {
    case kDNSServiceErr_NoError:
      DPRINTF(E_DBG, L_MDNS, "Successfully added mDNS cname\n");
      break;

    case kDNSServiceErr_NameConflict:
      DPRINTF(E_DBG, L_MDNS, "Name collision - automatically assigning new name\n");
      break;

    case kDNSServiceErr_NoMemory:
      DPRINTF(E_DBG, L_MDNS, "Out of memory registering cname record\n");
      break;

    default:
      DPRINTF(E_DBG, L_MDNS, "Unspecified error registering cname record\n");
	}
}

int
mdns_cname(char *name)
{
  char hostname[HOST_NAME_MAX + 1];
  char rdata[HOST_NAME_MAX + 6 + 1];
  int ret;
  DNSServiceErrorType err;

  DPRINTF(E_DBG, L_MDNS, "Adding CNAME record %s\n", name);

  ret = gethostname(hostname, HOST_NAME_MAX);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_MDNS, "Could not add CNAME %s, gethostname failed\n", name);
      return -1;
    }

  // Note, gethostname does not guarantee 0-termination
  if (strnstr(hostname, ".local", sizeof(hostname)) != NULL)
	  // hostname already contains .local suffix
	ret = snprintf(rdata, sizeof(rdata), ".%s", hostname);
  else
    ret = snprintf(rdata, sizeof(rdata), ".%s.local", hostname);
  if (!(ret > 0 && ret < sizeof(rdata)))
  {
    DPRINTF(E_LOG, L_MDNS, "Could not add CNAME %s, hostname is invalid\n", name);
    return -1;
  }

  err = DNSServiceRegisterRecord(sdref_main, &rref_main, kDNSServiceFlagsShared, 0, name, kDNSServiceType_CNAME, kDNSServiceClass_IN, ret, rdata, 0, cname_callback, NULL);
  if (err != kDNSServiceErr_NoError)
    {
      DPRINTF(E_LOG, L_MDNS, "Could not add CNAME record %s: %d\n", name, err);
      return -1;
    }

  return 0;
}

static void
lookup_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
        DNSServiceErrorType errorCode, const char *hostname, const struct sockaddr *address,
        uint32_t ttl, void *context )
{
  struct mdns_addr_lookup *lu;
  int ll;
  struct sockaddr_in *addr;
  struct sockaddr_in6 *addr6;
  char addr_str[INET6_ADDRSTRLEN];

  if (errorCode != kDNSServiceErr_NoError )
    {
      DPRINTF(E_LOG, L_MDNS, "Error resolving service address\n");
      return;
    }

  if (flags & kDNSServiceFlagsAdd)
    {
      lu = (struct mdns_addr_lookup *)context;

      if (address->sa_family == AF_INET)
        {
          addr = (struct sockaddr_in *)address;

          ll = is_v4ll(&addr->sin_addr);
          if (ll && !(lu->mb->flags & MDNS_WANT_V4LL))
            {
              DPRINTF(E_DBG, L_MDNS, "Discarding IPv4 LL, not interested (service %s)\n", lu->name);
              goto check_free;
            }
          else if (!ll && !(lu->mb->flags & MDNS_WANT_V4))
            {
              DPRINTF(E_DBG, L_MDNS, "Discarding IPv4, not interested (service %s)\n", lu->name);
              goto check_free;
            }

          if (!inet_ntop(AF_INET, &addr->sin_addr, addr_str, sizeof(addr_str)))
            {
                DPRINTF(E_LOG, L_MDNS, "Could not print IPv4 address: %s\n", strerror(errno));
                goto check_free;
            }
        }
      else if (address->sa_family == AF_INET6)
        {
          addr = (struct sockaddr_in *)address;
          addr6 = (struct sockaddr_in6 *)address;

          ll = is_v6ll(&addr6->sin6_addr);
          if (ll && !(lu->mb->flags & MDNS_WANT_V6LL))
            {
              DPRINTF(E_DBG, L_MDNS, "Discarding IPv6 LL, not interested (service %s)\n", lu->name);
              goto check_free;
            }
          else if (!ll && !(lu->mb->flags & MDNS_WANT_V6))
            {
              DPRINTF(E_DBG, L_MDNS, "Discarding IPv6, not interested (service %s)\n", lu->name);
              goto check_free;
            }

          if (!inet_ntop(AF_INET6, &addr6->sin6_addr, addr_str, sizeof(addr_str)))
            {
                DPRINTF(E_LOG, L_MDNS, "Could not print IPv6 address: %s\n", strerror(errno));
                goto check_free;
            }
        }

      DPRINTF(E_DBG, L_MDNS, "Service %s, hostname %s resolved to %s\n", lu->name, hostname, addr_str);

      /* Execute callback (mb->cb) with all the data */
      lu->mb->cb(lu->name, lu->mb->type, lu->domain, hostname, address->sa_family, addr_str, lu->port, &lu->txt_kv);
    }

 check_free: /* If we are done with address lookups for this resolve, terminate the address lookup */
  if (!(flags & kDNSServiceFlagsMoreComing))
    {
      DNSServiceRefDeallocate(lu->sdref);
      event_del(lu->ev);
      #ifdef HAVE_LIBEVENT2
        event_free(lu->ev);
      #else
        free(lu->ev);
      #endif
      keyval_clear(&lu->txt_kv);
      free(lu->name);
      free(lu->type);
      free(lu->domain);
      free(lu);
    }
}

static void
resolve_callback( DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
        DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget,
        uint16_t port, uint16_t txtLen, const unsigned char *txtRecord, void *context )
{
  struct mdns_resolver *rs;
  DNSServiceErrorType err;
  DNSServiceProtocol proto = 0;
  struct mdns_addr_lookup *lu;
  char key[256];
  int i;
  uint8_t valueLen;
  const char *value;
  int ret;
  int fd;

  if (errorCode != kDNSServiceErr_NoError )
    {
      DPRINTF(E_LOG, L_MDNS, "Error resolving mdns service\n");
      return;
    }

  rs = (struct mdns_resolver *)context;

  if (rs->mb->flags & (MDNS_WANT_V4 | MDNS_WANT_V4LL))
    {
      proto |= kDNSServiceProtocol_IPv4;
    }

  if (rs->mb->flags & (MDNS_WANT_V6 | MDNS_WANT_V6LL))
      {
        proto |= kDNSServiceProtocol_IPv6;
      }

  lu = (struct mdns_addr_lookup *)malloc(sizeof(struct mdns_addr_lookup));
  if (!lu)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory creating address lookup.\n");
      goto check_free;
    }

  lu->name = strdup(rs->name);
  if (!lu->name)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory creating address lookup.\n");
      free(lu);
      goto check_free;
    }
  lu->type = strdup(rs->type);
  if (!lu->type)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory creating address lookup.\n");
      free(lu->name);
      free(lu);
      goto check_free;
    }
  lu->domain = strdup(rs->domain);
  if (!lu->domain)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory creating address lookup.\n");
      free(lu->type);
      free(lu->name);
      free(lu);
      goto check_free;
    }
  lu->port = port;
  lu->mb = rs->mb;

  for (i=0; TXTRecordGetItemAtIndex(txtLen, txtRecord, i, 256, key, &valueLen, (const void **)&value) != kDNSServiceErr_Invalid; i++ )
    {
      ret = keyval_add_size(&lu->txt_kv, key, value, valueLen);
      if (ret < 0)
        {
          DPRINTF(E_LOG, L_MDNS, "Could not build TXT record keyval\n");
          goto error_out;
        }
    }

  lu->sdref = sdref_main;
  err = DNSServiceGetAddrInfo(&lu->sdref, kDNSServiceFlagsShareConnection, interfaceIndex, proto, hosttarget, lookup_callback, lu);
  if (err != kDNSServiceErr_NoError)
    {
      DPRINTF(E_LOG, L_MDNS, "Failed to create service resolver.\n");
      goto error_out;
    }

  fd = DNSServiceRefSockFD(lu->sdref);
#ifdef HAVE_LIBEVENT2
  lu->ev = event_new(evbase_main, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &lu->sdref);
  if (!lu->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Could not make new event in browse_callback\n");
      DNSServiceRefDeallocate(lu->sdref);
      goto error_out;
    }
#else
  lu->ev = (struct event *)malloc(sizeof(struct event));
  if (!lu->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory in browse_callback\n");
      DNSServiceRefDeallocate(lu->sdref);
      goto error_out;
    }

  event_set(lu->ev, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &lu->sdref);
  event_base_set(evbase_main, lu->ev);
#endif

  event_add(lu->ev, NULL);
  goto check_free;

 error_out:
  keyval_clear(&lu->txt_kv);
  free(lu->name);
  free(lu->type);
  free(lu->domain);
  free(lu);

 check_free: /* If we are done resolving this service, terminate the resolve and free the resolver resources */
  if (!(flags & kDNSServiceFlagsMoreComing))
    {
      DNSServiceRefDeallocate(rs->sdref);
      event_del(rs->ev);
      #ifdef HAVE_LIBEVENT2
        event_free(rs->ev);
      #else
        free(rs->ev);
      #endif
      free(rs->name);
      free(rs->type);
      free(rs->domain);
      free(rs);
    }
}

static void
browse_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
        DNSServiceErrorType errorCode, const char *serviceName, const char *regtype,
        const char *replyDomain, void *context )
{
  struct mdns_browser *mb;
  DNSServiceErrorType err;
  int fd;
  struct mdns_resolver *rs;

  if (errorCode != kDNSServiceErr_NoError)
    {
      DPRINTF(E_LOG, L_MDNS, "DNS-SD browsing error %d\n", errorCode);
      return;
    }

  mb = (struct mdns_browser *)context;

  if (flags & kDNSServiceFlagsAdd)
    {
      DPRINTF(E_DBG, L_MDNS, "DNS-SD Browser: NEW service '%s' type '%s' interface %d\n", serviceName, regtype, interfaceIndex);

      rs = (struct mdns_resolver *)malloc(sizeof(struct mdns_resolver));
      if (!rs)
        {
          DPRINTF(E_LOG, L_MDNS, "Out of memory creating service resolver.\n");
          return;
        }

      rs->name = strdup(serviceName);
      if (!rs->name)
        {
          DPRINTF(E_LOG, L_MDNS, "Out of memory creating service resolver.\n");
          free(rs);
          return;
        }
      rs->type = strdup(regtype);
      if (!rs->type)
        {
          DPRINTF(E_LOG, L_MDNS, "Out of memory creating service resolver.\n");
          free(rs->name);
          free(rs);
          return;
        }
      rs->domain = strdup(replyDomain);
      if (!rs->name)
        {
          DPRINTF(E_LOG, L_MDNS, "Out of memory creating service resolver.\n");
          free(rs->type);
          free(rs->name);
          free(rs);
          return;
        }
      rs->mb = mb;

      rs->sdref = sdref_main;
      err = DNSServiceResolve(&(rs->sdref), kDNSServiceFlagsShareConnection, interfaceIndex, serviceName, regtype, replyDomain, resolve_callback, rs);
      if (err != kDNSServiceErr_NoError)
        {
          DPRINTF(E_LOG, L_MDNS, "Failed to create service resolver.\n");
          goto error_out;
        }

      fd = DNSServiceRefSockFD(rs->sdref);
    #ifdef HAVE_LIBEVENT2
      rs->ev = event_new(evbase_main, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &rs->sdref);
      if (!rs->ev)
        {
          DPRINTF(E_LOG, L_MDNS, "Could not make new event in browse_callback\n");
          DNSServiceRefDeallocate(rs->sdref);
          goto error_out;
          return;
        }
    #else
      rs->ev = (struct event *)malloc(sizeof(struct event));
      if (!rs->ev)
        {
          DPRINTF(E_LOG, L_MDNS, "Out of memory in browse_callback\n");
          DNSServiceRefDeallocate(rs->sdref);
          goto error_out;
          return;
        }

      event_set(rs->ev, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &rs->sdref);
      event_base_set(evbase_main, rs->ev);
    #endif

      event_add(rs->ev, NULL);
      return;

     error_out:
      free(rs->name);
      free(rs->type);
      free(rs->domain);
      free(rs);
    }
  else
    {
      DPRINTF(E_DBG, L_MDNS, "Avahi Browser: REMOVE service '%s' type '%s' interface %d\n", serviceName, regtype, interfaceIndex);
      mb->cb(serviceName, regtype, replyDomain, NULL, 0, NULL, -1, NULL);
    }
}

int
mdns_browse(char *type, int flags, mdns_browse_cb cb)
{
  struct mdns_browser *mb;
  DNSServiceErrorType err;
  int fd;

  DPRINTF(E_DBG, L_MDNS, "Adding service browser for type %s\n", type);

  mb = (struct mdns_browser *)malloc(sizeof(struct mdns_browser));
  if (!mb)
    return -1;

  mb->type = strdup(type);
  if (!(mb->type))
    {
      free(mb);
      return -1;
    }
  mb->cb = cb;

  /* flags are ignored in DNS-SD implementation */
  mb->flags = (flags) ? flags : MDNS_WANT_DEFAULT;

  mb->sdref = sdref_main;
  err = DNSServiceBrowse(&(mb->sdref), kDNSServiceFlagsShareConnection, 0, type, NULL, browse_callback, mb);
  if (err != kDNSServiceErr_NoError)
    {
      DPRINTF(E_LOG, L_MDNS, "Failed to create service browser.\n");

      free(mb->type);
      free(mb);

      return -1;
    }

  fd = DNSServiceRefSockFD(mb->sdref);
#ifdef HAVE_LIBEVENT2
  mb->ev = event_new(evbase_main, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &mb->sdref);
  if (!mb->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Could not make new event in mdns_browse\n");

      DNSServiceRefDeallocate(mb->sdref);
      free(mb->type);
      free(mb);

      return -1;
    }
#else
  mb->ev = (struct event *)malloc(sizeof(struct event));
  if (!mb->ev)
    {
      DPRINTF(E_LOG, L_MDNS, "Out of memory in mdns_browse\n");

      DNSServiceRefDeallocate(mb->sdref);
      free(mb->type);
      free(mb);

      return -1;
    }

  event_set(mb->ev, fd, EV_PERSIST | EV_READ, ev_dnssd_cb, &mb->sdref);
  event_base_set(evbase_main, mb->ev);
#endif

  return event_add(mb->ev, NULL);

  mb->next = browser_list;
  browser_list = mb;

  return 0;
}
