#include <libsoup/soup.h>
#include <string.h>
#include <stdlib.h>

#define URL "http://localhost/adminer.php"
/* #define URL "http://localhost/test.php" */
#define USERNAME "root"
#define PASSWORD "pebble"
#define DATABASE "agenturhalma"

#define BUFSIZE 16 * 8192

static void build_form_data(const gchar *table_name, GString *form_data) {
	g_string_append_printf(form_data, "data[]=%s&table[]=%s&", table_name, table_name);
}

static void dump_response(GInputStream *istream) {
	GError *error;
	gsize len;
	gchar buffer[BUFSIZE];

	do {
		error = NULL;
		len = g_input_stream_read(istream, buffer, sizeof(buffer), NULL, &error);
		if (error) {
			g_error("Failed: %s\n", error->message);
			g_error_free(error);
			exit(-1);
		}
		buffer[len] = '\0';
		g_print("%s", buffer);
	} while (len > 0);
}

static void on_authenticate(SoupSession *session, SoupMessage *message, SoupAuth *auth, gboolean retrying, gpointer user_data) {
	g_debug("Authenticate!");
	exit(0);
}

int main(int argc, char **argv) {
	SoupSession *session;
	SoupMessage *message;
	SoupCookieJar *cookiejar;
	GError *error;
	GInputStream *istream;
	gchar buffer[BUFSIZE];

	char formdata[8192];
	/* g_snprintf(formdata, sizeof(formdata), "username=%s&password=%s&database=%s", USERNAME, PASSWORD, DATABASE); */
	g_snprintf(formdata, sizeof(formdata), 
			"auth[driver]=%s&"
			"auth[server]=%s&"
			"auth[username]=%s&"
			"auth[password]=%s&"
			"auth[db]=%s",
			"server",
			"",
			USERNAME,
			PASSWORD,
			DATABASE
	);
	g_debug("%s", formdata);

	session = soup_session_new();
	cookiejar = soup_cookie_jar_new();
	soup_cookie_jar_set_accept_policy(cookiejar, SOUP_COOKIE_JAR_ACCEPT_ALWAYS);

	soup_session_add_feature(session, SOUP_SESSION_FEATURE(cookiejar));
	g_object_unref(cookiejar);

	message = soup_message_new("POST", URL);
	soup_message_set_request(message, "application/x-www-form-urlencoded",
			SOUP_MEMORY_COPY, formdata, strlen(formdata));

	g_signal_connect(session, "authenticate", G_CALLBACK(on_authenticate), NULL);

	/* soup_message_headers_append(msg->request_headers, "Refere", */

	error = NULL;
	istream = soup_session_send(session, message, NULL, &error);

	/* g_print("status: %u\n", message->status_code); */

	if (message->status_code != 200) {
		g_error("Server returned %u\n", message->status_code);
		exit(-1);
	}

	gsize len;
	g_input_stream_read_all(istream, buffer, sizeof(buffer), &len, NULL, &error);
	if (error != NULL) {
		g_error("%s", error->message);
	}
	
	/* do { */
	/* 	error = NULL; */
	/* 	len = g_input_stream_read(istream, buffer, sizeof(buffer), NULL, &error); */
	/* 	if (error) { */
	/* 		g_error("Failed: %s\n", error->message); */
	/* 		g_error_free(error); */
	/* 		exit(-1); */
	/* 	} */
	/* 	buffer[len] = '\0'; */
	/* 	#<{(| g_print("%s", buffer); |)}># */
	/* 	g_print("%u bytes read\n", (int)len); */
	/* } while (len > 0); */

	error = NULL;
	g_input_stream_close(istream, NULL, &error);

	GRegex *regex;
	GMatchInfo *match_info;
	gchar *token;

	regex = g_regex_new("token.*value=\"(.*)\"", 0, 0, &error);
	g_regex_match(regex, buffer, 0, &match_info);
	if (!g_match_info_matches(match_info)) {
		g_error("No match!");
	}
	while (g_match_info_matches(match_info)) {
		gchar *result = g_match_info_fetch(match_info, 1);
		token = g_strdup(result);
		g_match_info_next(match_info, &error);
		g_free(result);
		break;
	}

	g_debug("%s\n", token);
	
	SoupMessage *message2;
	gchar *url;
	url = g_strdup_printf("%s?username=%s&db=%s&dump=", URL, USERNAME, DATABASE);
	g_debug("%s\n", url);

	message2 = soup_message_new("GET", url);

	/* soup_message_set_request(message2, "application/x-www-form-urlencoded", SOUP_MEMORY_COPY, NULL, 0); */

	error = NULL;
	istream = soup_session_send(session, message2, NULL, &error);
	
	/* dump_response(istream); */
	/* exit(0); */

	gchar form[BUFSIZE];
	g_input_stream_read_all(istream, form, sizeof(form), &len, NULL, &error);
	if (error != NULL) {
		g_error("%s", error->message);
	}
	regex = g_regex_new("checkbox.*name='data\\[\\]'.*value='(.*)'", 0, 0, &error);
	g_regex_match(regex, form, 0, &match_info);
	if (!g_match_info_matches(match_info)) {
		g_error("No match!");
	}

	GList *tables = NULL;

	while (g_match_info_matches(match_info)) {
		gchar *result = g_match_info_fetch(match_info, 1);
		tables = g_list_append(tables, g_strdup(result));
		g_match_info_next(match_info, &error);
		/* g_print("%s\n", result); */
		g_free(result);
	}

	GString *form_data;
	form_data = g_string_new(NULL);

	g_list_foreach(tables, (GFunc)build_form_data, form_data);
	g_string_append_printf(form_data, "token=%s&", token);
	g_print("%s\n", form_data->str);
	return 0;
}
