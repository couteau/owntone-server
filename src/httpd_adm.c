/*
 * Copyright (C) 2014 Stuart NAIFEH <stu@naifeh.org>
 *
 * Adapted from httpd_daap.c and httpd.c:
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2010 Kai Elwert <elwertk@googlemail.com>
 *
 * Adapted from mt-daapd:
 * Copyright (C) 2003-2007 Ron Pedde <ron@pedde.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>
#include <regex.h>
#include <event.h>
#include <confuse.h>

#include "logger.h"
#include "misc.h"
#include "conffile.h"
#include "artwork.h"
#include "httpd.h"
#include "httpd_adm.h"
#include "db.h"
#include "player.h"

#define WEBROOT DATADIR

struct uri_map {
	regex_t preg;
	char *regexp;
	void (*handler)(struct evhttp_request *req, struct evbuffer *evbuf,
			char *uri, struct evkeyvalq *query);
};

/* Check authentication */
static int check_auth(struct evhttp_request *req) {
	char * passwd;
	const char * host;
	int ret = 0;

	passwd = cfg_getstr(cfg_getsec(cfg, "general"), "admin_password");
	if (passwd) {
		DPRINTF(E_DBG, L_ADMIN, "Checking web interface authentication\n");

		ret = httpd_basic_auth(req, "admin", passwd, PACKAGE " web interface");
		if (ret == 0) {
			DPRINTF(E_DBG, L_ADMIN, "Authentication successful\n");
		} else {
			DPRINTF(E_DBG, L_ADMIN, "Authentication failed");
		}
	} else {
		host = evhttp_request_get_host(req);
		if ((strcmp(host, "::1") != 0) && (strcmp(host, "127.0.0.1") != 0)) {
			DPRINTF(E_LOG, L_ADMIN,
					"Remote admin interface request denied; no password set\n");

			evhttp_send_error(req, 403, "Forbidden");

			ret = -1;
		}
	}

	return ret;
}

extern struct event_base *evbase_main;

static void restart_httpd_cb(int fd, short event, void *arg) {
	DPRINTF(E_DBG, L_ADMIN, "Restarting HTTP thread...\n");
	httpd_deinit();
	if (httpd_init() != 0) {
		DPRINTF(E_FATAL, L_ADMIN, "HTTPd thread failed to restart\n");
		event_base_loopbreak(evbase_main); //abort main loop
	}
	/* TODO: If port changed, we need to re-register the bonjour services.
	 *       Currently, starting bonjour services is done in a static function in main.c, so no way to call from here. */
}

static int httpd_reinit() {
	/* TODO: This won't work well unless we enable libevent thread awareness in main.c (a libevent2 feature) */
	return event_base_once(evbase_main, -1, EV_TIMEOUT, restart_httpd_cb, NULL,
			NULL);
}

static int restart_logger(const char * logfile, int loglevel) {
	int detach = 0;
	struct stat sb;

	/* TODO: preserve logging options set on command line
	 * TODO: make thread safe -- logger_deinit()/logger_init() assume single threaded mode
	 *       Calling them when multiple threads are accessing the log is dangerous
	 *        -- unlike logger_reinit(), they do not do any concurrency.
	 *       logger_reinit() does not allow for modifying logging options, however.
	 */
	logger_deinit();
	if (!logfile) {
		logfile = cfg_getstr(cfg_getsec(cfg, "general"), "logfile");
	}

	if (loglevel == -1) {
		loglevel = cfg_getint(cfg_getsec(cfg, "general"), "loglevel");
	}

	/* First set effective uid back to root if possible. */
	if (getuid() == 0 && geteuid() != 0) {
		seteuid(0);
	}

/* TODO: make this portable */
#ifdef __linux__
#include <linux/kdev_t.h>
	if (fstat(STDOUT_FILENO, &sb) == 0) {
		detach = (sb.st_rdev == MKDEV(1,3)); // is stdout pointing to /dev/null?
	}
#endif

	if (logger_init((char *) logfile, NULL, loglevel) == 0) {
		if (detach) {
			logger_detach();
		}
		cfg_setstr(cfg_getsec(cfg, "general"), "logfile", logfile);
		cfg_setint(cfg_getsec(cfg, "general"), "loglevel", loglevel);
	}
	else {
		/* If we could not set new log parameters, reinit the logger using the original parameters. */
		logger_reinit();
	}

	if (geteuid() == 0 && runas_uid != 0) {
		seteuid(runas_uid);
	}

	return 0;
}

static int trigger_rescan(int full) {
	int tmpfile, n;
	char buf[PATH_MAX];

	/* create a temp file ending in ".full-rescan" or ".init-rescan" in the first directory in the library list */
	n = snprintf(buf, sizeof(buf), "%s/tmpXXXXXX.%s-rescan",
			cfg_getstr(cfg_getsec(cfg, "library"), "directories"),
			full ? "full" : "init");
	if ((n < 0) || (n >= sizeof(buf))) {
		return -1;
	}

	tmpfile = mkstemps(buf, 12);
	if (tmpfile < 0) {
		return -1;
	}

	/* TODO: figure out a way to delete the file once the scan has been triggered
	 *       (or how to trigger a scan without having to create a temp file) */
	close(tmpfile);
	return 0;
}

static int parse_dirs(const char *str, const char * section) {
	cfg_t *sec;
	char *dirs, *dir, *ptr;

	dirs = strdup(str);
	if (!dirs) {
		DPRINTF(E_LOG, L_ADMIN, "Error setting %s", section);
		return -1;
	}

	/* TODO: Validate the directories as we go */
	if ((dir = strtok_r(dirs, ":", &ptr))) {
		sec = cfg_getsec(cfg, "library");
		DPRINTF(E_DBG, L_ADMIN, "Found new %s directory: %s.\n", section, dir);
		cfg_setlist(sec, section, 1, dir);
		while ((dir = strtok_r(NULL, ":", &ptr))) {
			DPRINTF(E_DBG, L_ADMIN, "Found new %s directory: %s.\n", section,
					dir);
			cfg_addlist(sec, section, 1, dir);
		}
	}
	free(dirs);
	return 0;
}

static void adm_reply_setconfig(struct evhttp_request *req,
		struct evbuffer *evbuf, char *uri, struct evkeyvalq *query) {
	/* /admin/setconfig */
	int ret;
	char *data;
	size_t len;
	struct evbuffer *in_evbuf;
	struct evkeyvalq postvars;
	const char *logfile = NULL, *param;
	int restart_logging = 0, restart_httpd = 0, rescan = -1;
	int loglevel = -1, port, ipv6;

	ret = check_auth(req);
	if (ret < 0) {
		return;
	}

	/* configuration parameters must be sent in a POST request */
	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
		return;
	}

	in_evbuf = evhttp_request_get_input_buffer(req);
	if (!in_evbuf) {
		goto out_fail;
	}
	len = evbuffer_get_length(in_evbuf);
	data = malloc(len + 1);
	if (!data) {
		goto out_fail;
	}
	ret = evbuffer_copyout(in_evbuf, data, len);
	if (ret < 0) {
		free(data);
		goto out_fail;
	}
	data[len] = '\0';

	DPRINTF(E_DBG, L_ADMIN, "POST dump: %s\n", data);

	ret = evhttp_parse_query_str(data, &postvars);
	if (ret < 0) {
		free(data);
		goto out_fail;
	}

	param = evhttp_find_header(&postvars, "directories");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting directories to: %s.\n", param);
		if (parse_dirs(param, "directories") != 0) {
			goto fail_clear_vars;
		}
		rescan = 0;
	}

	param = evhttp_find_header(&postvars, "podcasts");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting podcasts to: %s.\n", param);
		if (parse_dirs(param, "podcasts") != 0) {
			goto fail_clear_vars;
		}
		rescan = 1; // for now, changes to special dirs require a full rescan to get picked up
	}

	param = evhttp_find_header(&postvars, "audiobooks");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting audiobooks to: %s.\n", param);
		if (parse_dirs(param, "audiobooks") != 0) {
			goto fail_clear_vars;
		}
		rescan = 1; // for now, changes to special dirs require a full rescan to get picked up
	}

	param = evhttp_find_header(&postvars, "compilations");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting compilations to: %s.\n", param);
		if (parse_dirs(param, "compilations") != 0) {
			goto fail_clear_vars;
		}
		rescan = 1; // for now, changes to special dirs require a full rescan to get picked up
	}

	param = evhttp_find_header(&postvars, "compilation_artist");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting compilation_artist to: %s.\n", param);
		cfg_setstr(cfg_getsec(cfg, "library"), "compilation_artist", param);
		rescan = 1; // for now, changes to special dirs require a full rescan to get picked up
	}

	logfile = evhttp_find_header(&postvars, "logfile");
	if (logfile) {
		DPRINTF(E_DBG, L_ADMIN, "Setting logfile to: %s.\n", logfile);
		restart_logging = 1;
	}

	param = evhttp_find_header(&postvars, "loglevel");
	if (param) {
		DPRINTF(E_DBG, L_ADMIN, "Setting loglevel to: %s.\n", param);
		safe_atoi32(param, &loglevel);
		restart_logging = 1;
	}

	param = evhttp_find_header(&postvars, "port");
	if (param) {
		if (safe_atoi32(param, &port) == 0) {
			DPRINTF(E_DBG, L_ADMIN, "Setting port to: %s.\n", param);
			cfg_setint(cfg_getsec(cfg, "library"), "port", port);
			restart_httpd = 1;
		} else
			DPRINTF(E_LOG, L_ADMIN, "Invalid integer value for port: %s.\n",
					param);
	}

	param = evhttp_find_header(&postvars, "ipv6");
	if (param) {
		if (safe_atoi32(param, &ipv6) == 0) {
			DPRINTF(E_DBG, L_ADMIN, "Setting ipv6 to: %s.\n",
					ipv6 ? "yes" : "no");
			cfg_setbool(cfg_getsec(cfg, "general"), "ipv6", ipv6);
			restart_httpd = 1;
		} else
			DPRINTF(E_LOG, L_ADMIN, "Invalid integer value for ipv6: %s.\n",
					param);
	}

	if (restart_logging) {
		restart_logger(logfile, loglevel);
	}

	if (restart_httpd)
		httpd_reinit();

	if (rescan != -1)
		trigger_rescan(rescan);

	evhttp_send_reply(req, HTTP_NOCONTENT, "No Content", evbuf);
	evhttp_clear_headers(&postvars);
	free(data);
	return;

 fail_clear_vars:
	evhttp_clear_headers(&postvars);
	free(data);
 out_fail:
	evhttp_send_error(req, 500, "Internal Server Error");
}

static void adm_reply_rescan(struct evhttp_request *req, struct evbuffer *evbuf,
		char *uri, struct evkeyvalq *query) {
	/* /admin/fullrescan */
	/* /admin/initrescan */
	int ret;

	ret = check_auth(req);
	if (ret < 0) {
		return;
	}

	if (trigger_rescan(strstr(uri, "full") != NULL) != 0) {
		DPRINTF(E_LOG, L_ADMIN, "Could not trigger library re-scan.\n");
		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	/* 204 No Content is the canonical reply */
	evhttp_send_reply(req, HTTP_NOCONTENT, "No Content", evbuf);
	return;
}

#define CONFIGFMT_JSON "{\"logfile\" : \"%s\", \"loglevel\" : %d, " \
		  "\"ipv6\" : %d, \"daapcache_threshold\" : %d, \"name\" : \"%s\", \"port\" : \"%d\", " \
        "\"directories\" : [ %s ], \"podcasts\" : [ %s ], \"audiobooks\" : [ %s ], " \
	      "\"compilations\" : [ %s ], \"compilation_artist\" : \"%s\" }"

static void adm_reply_getconfig(struct evhttp_request *req,
		struct evbuffer *evbuf, char *uri, struct evkeyvalq *query) {
	/* /admin/getconfig */
	struct evkeyvalq *headers;
	int ret, ndirs, i, n;
	char directories[1024];
	char podcasts[1024];
	char audiobooks[1024];
	char compilations[1024];
	cfg_t *sec;
	int loglevel, port, ipv6, daapcache_threshold;
	char *logfile, *libname, *compilation_artist;

	ret = check_auth(req);
	if (ret < 0) {
		return;
	}

	sec = cfg_getsec(cfg, "general");
	loglevel = cfg_getint(sec, "loglevel");
	logfile = cfg_getstr(sec, "logfile");
	ipv6 = cfg_getbool(sec, "ipv6");
	daapcache_threshold = cfg_getint(sec, "cache_daap_threshold");

	sec = cfg_getsec(cfg, "library");
	libname = cfg_getstr(sec, "name");
	port = cfg_getint(sec, "port");

	ndirs = cfg_size(sec, "directories");
	if (ndirs) {
		n = snprintf(directories, sizeof(directories), "\"%s\"",
				cfg_getnstr(sec, "directories", 0));
		for (i = 1; i < ndirs; i++) {
			n += snprintf(directories + n, sizeof(directories) - n, ", \"%s\"",
					cfg_getnstr(sec, "directories", i));
		}
	}

	ndirs = cfg_size(sec, "podcasts");
	if (ndirs) {
		n = snprintf(podcasts, sizeof(podcasts), "\"%s\"",
				cfg_getnstr(sec, "podcasts", 0));
		for (i = 1; i < ndirs; i++) {
			n += snprintf(podcasts + n, sizeof(podcasts) - n, ", \"%s\"",
					cfg_getnstr(sec, "podcasts", i));
		}
	}

	ndirs = cfg_size(sec, "audiobooks");
	if (ndirs) {
		n = snprintf(audiobooks, sizeof(audiobooks), "\"%s\"",
				cfg_getnstr(sec, "audiobooks", 0));
		for (i = 1; i < ndirs; i++) {
			n += snprintf(audiobooks + n, sizeof(audiobooks) - n, ", \"%s\"",
					cfg_getnstr(sec, "audiobooks", i));
		}
	}

	ndirs = cfg_size(sec, "compilations");
	if (ndirs) {
		n = snprintf(compilations, sizeof(compilations), "\"%s\"",
				cfg_getnstr(sec, "compilations", 0));
		for (i = 1; i < ndirs; i++) {
			n += snprintf(compilations + n, sizeof(compilations) - n,
					", \"%s\"", cfg_getnstr(sec, "compilations", i));
		}
	}

	compilation_artist = cfg_getstr(sec, "compilation_artist");

	n = evbuffer_add_printf(evbuf, CONFIGFMT_JSON, logfile, loglevel, ipv6,
			daapcache_threshold, libname, port, directories, podcasts,
			audiobooks, compilations, compilation_artist);

	if (n < 0) {
		DPRINTF(E_LOG, L_ADMIN,
				"getconfig: Couldn't add configuration data to response buffer.\n");

		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(headers, "Content-Type", "application/json");
	httpd_send_reply(req, HTTP_OK, "OK", evbuf);
	return;
}

#define STATUSFMT_JSON "{ \"name\" : \"%s\", \"uptime\" : %lld, \"filescanner\" : %d, " \
	      "\"version\" : \"%s\", \"db_version\" : %s, " \
	      "\"total_songs\" : %d, \"total_playlists\" : %d, \"play_status\" : %d }"

static void adm_reply_getstatus(struct evhttp_request *req,
		struct evbuffer *evbuf, char *uri, struct evkeyvalq *query) {
	/* /admin/getstatus */

	int ret;
	struct evkeyvalq *headers;
	char *libname;
	char *start_time;
	time_t start;
	long long uptime = 0;
	int filescanner = 0; /* TODO: figure out how to determine filescanner status */
	int files;
	int pls;
	struct player_status ps;
	char *db_version;

	ret = check_auth(req);
	if (ret < 0) {
		return;
	}

	libname = cfg_getstr(cfg_getsec(cfg, "library"), "name");
	files = db_files_get_count();
	pls = db_pl_get_count();
	start_time = db_admin_get("adm_start");
	if (safe_atoi64(start_time, &start) == 0) {
		uptime = time(NULL) - start;
	}
	free(start_time);
	db_version = db_admin_get("schema_version");
	player_get_status(&ps);

	ret = evbuffer_add_printf(evbuf, STATUSFMT_JSON, libname, uptime,
			filescanner, VERSION, db_version, files, pls, ps.status);
	free(db_version);

	if (ret < 0) {
		DPRINTF(E_LOG, L_ADMIN,
				"getstatus: Couldn't add status data to response buffer.\n");

		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(headers, "Content-Type", "application/json");
	httpd_send_reply(req, HTTP_OK, "OK", evbuf);
	return;
}

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] =
		{ { "txt", "text/plain" },
		  { "c", "text/plain" },
		  { "h", "text/plain" },
		  { "html", "text/html" },
		  { "htm", "text/html" },
		  { "css", "text/css" },
		  { "gif", "image/gif" },
		  { "jpg", "image/jpeg" },
		  { "jpeg", "image/jpeg" },
		  { "png", "image/png" },
		  { "pdf", "application/pdf" },
		  { "ps", "application/postscript" },
		  { NULL, NULL }, };

/* Try to guess a good content-type for 'path' */
static const char *
guess_content_type(const char *path) {
	const char *last_period, *extension;
	const struct table_entry *ent;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		goto not_found;
	/* no exension */
	extension = last_period + 1;
	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}

 not_found:
	return "application/misc";
}

static void adm_reply_file(struct evhttp_request *req, struct evbuffer *evbuf,
		char *uri, struct evkeyvalq *query) {
	/* /admin/* */
	int ret;
	char path[PATH_MAX];
	struct evkeyvalq *headers;
	struct stat sb;
	int fd;

	ret = check_auth(req);
	if (ret < 0) {
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
		evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
		return;
	}

	ret = snprintf(path, sizeof(path), "%s%s", WEBROOT, uri);
	if ((ret < 0) || (ret >= sizeof(path))) {
		DPRINTF(E_LOG, L_ADMIN, "Request exceeds PATH_MAX: %s%s\n", WEBROOT,
				uri);

		evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");

		return;
	}

	ret = stat(path, &sb);
	if (ret < 0) {
		DPRINTF(E_LOG, L_ADMIN, "Could not stat() %s: %s\n", path,
				strerror(errno));

		evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");

		return;
	}

	if (S_ISDIR(sb.st_mode)) {
		if (strlen(path) > sizeof(path) - 12) {
			DPRINTF(E_LOG, L_ADMIN, "Request exceeds PATH_MAX: %s%s\n", WEBROOT,
					uri);

			evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");

			return;
		}

		if (path[strlen(path) - 1] != '/') {
			strcat(path, "/");
		}

		strcat(path, "index.html");

		ret = stat(path, &sb);
		if (ret < 0) {
			DPRINTF(E_LOG, L_ADMIN, "Could not stat() %s: %s\n", path,
					strerror(errno));

			evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
			return;
		}
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		DPRINTF(E_LOG, L_ADMIN, "Could not open %s: %s\n", path,
				strerror(errno));

		evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
		return;
	}

	ret = fstat(fd, &sb);
	if (ret < 0) {
		DPRINTF(E_LOG, L_ADMIN, "Could not fstat() %s: %s\n", path,
				strerror(errno));

		evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
		return;
	}

	ret = evbuffer_add_file(evbuf, fd, 0, sb.st_size); // evbuffer_add_file takes ownership of fd and closes it
	if (ret < 0) {
		DPRINTF(E_LOG, L_ADMIN, "Could not read file into evbuffer\n");

		evhttp_send_error(req, HTTP_SERVUNAVAIL, "Internal error");
		return;
	}

	headers = evhttp_request_get_output_headers(req);

	evhttp_add_header(headers, "Content-Type", guess_content_type(path));
	evhttp_send_reply(req, HTTP_OK, "OK", evbuf);
}

static struct uri_map adm_handlers[] = {
	{ .regexp = "^/admin/setconfig/?$", .handler = adm_reply_setconfig },
	{ .regexp = "^/admin/getconfig/?$", .handler = adm_reply_getconfig },
	{ .regexp = "^/admin/getstatus/?$", .handler = adm_reply_getstatus },
	{ .regexp = "^/admin/(full|init)rescan/?$", .handler = adm_reply_rescan },
	{ .regexp = "^/admin", .handler = adm_reply_file },
	{ .regexp = NULL, .handler = NULL } };

void adm_request(struct evhttp_request *req) {
	char *full_uri;
	char *uri;
	char *ptr;
	struct evbuffer *evbuf;
	struct evkeyvalq query;
	struct evkeyvalq *headers;
	int handler;
	int ret;
	int i;

	memset(&query, 0, sizeof(struct evkeyvalq));

	full_uri = httpd_fixup_uri(req);
	if (!full_uri) {
		evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
		return;
	}

	ptr = strchr(full_uri, '?');
	if (ptr)
		*ptr = '\0';

	uri = strdup(full_uri);
	if (!uri) {
		free(full_uri);
		evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
		return;
	}

	if (ptr)
		*ptr = '?';

	ptr = uri;
	uri = evhttp_decode_uri(uri);
	free(ptr);

	DPRINTF(E_DBG, L_ADMIN, "Web admin request: %s\n", full_uri);

	handler = -1;
	for (i = 0; adm_handlers[i].handler; i++) {
		ret = regexec(&adm_handlers[i].preg, uri, 0, NULL, 0);
		if (ret == 0) {
			handler = i;
			break;
		}
	}

	if (handler < 0) {
		DPRINTF(E_LOG, L_ADMIN, "Unrecognized web admin request\n");

		evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");

		free(uri);
		free(full_uri);
		return;
	}

	evbuf = evbuffer_new();
	if (!evbuf) {
		DPRINTF(E_LOG, L_ADMIN,
				"Could not allocate evbuffer for Web Admin reply\n");

		evhttp_send_error(req, HTTP_SERVUNAVAIL, "Internal Server Error");

		free(uri);
		free(full_uri);
		return;
	}

	evhttp_parse_query(full_uri, &query);

	headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(headers, "DAAP-Server", "forked-daapd/" VERSION);

	adm_handlers[handler].handler(req, evbuf, uri, &query);

	evbuffer_free(evbuf);
	evhttp_clear_headers(&query);
	free(uri);
	free(full_uri);
}

int adm_is_request(struct evhttp_request *req, char *uri) {
	if (strncmp(uri, "/admin", strlen("/admin")) == 0)
		return 1;

	return 0;
}

int adm_init(void) {
	char buf[64];
	int i;
	int ret;

	for (i = 0; adm_handlers[i].handler; i++) {
		ret = regcomp(&adm_handlers[i].preg, adm_handlers[i].regexp,
		REG_EXTENDED | REG_NOSUB);
		if (ret != 0) {
			regerror(ret, &adm_handlers[i].preg, buf, sizeof(buf));

			DPRINTF(E_FATAL, L_ADMIN,
					"Admin web interface init failed; regexp error: %s\n", buf);
			return -1;
		}
	}

	snprintf(buf, sizeof(buf), "%lld", (long long) time(NULL));
	db_admin_add("adm_start", buf);
	return 0;
}

void adm_deinit(void) {
	int i;

	db_admin_delete("adm_start");

	for (i = 0; adm_handlers[i].handler; i++)
		regfree(&adm_handlers[i].preg);

}
