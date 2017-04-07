#include <libsoup/soup.h>
#include <string.h>
#include <stdlib.h>

/* #define URL "http://localhost/adminer.php" */
/* #define URL "http://localhost/test.php" */
/* #define DATABASE "agenturhalma" */

#define BUFSIZE 16 * 8192

gchar *username;
gchar *password;
gchar *database;
gchar *url;
gchar *output = NULL;
gchar *format = "sql";
gchar *db_style = "";
gboolean routines = FALSE;
gboolean events = FALSE;
gchar *table_style = "DROP+CREATE";
gboolean triggers = FALSE;
gchar *data_style = "INSERT";
gboolean zip = FALSE;

static GOptionEntry entries[] = {
	{ "username", 'u', 0, G_OPTION_ARG_STRING, &username, "Username", NULL },
	{ "password", 'p', 0, G_OPTION_ARG_STRING, &password, "Password", NULL },
	{ "database", 'd', 0, G_OPTION_ARG_STRING, &database, "Database name", NULL },
	{ "output", 'o', 0, G_OPTION_ARG_STRING, &output, "Output to file", NULL },
	{ "format", 'f', 0, G_OPTION_ARG_STRING, &format, "Format (sql,csv,csv; or tsv)", NULL },
	{ "db-style", 's', 0, G_OPTION_ARG_STRING, &db_style, "Database style (USE, DROP+CREATE or CREATE)", NULL },
	{ "routines", 'r', 0, G_OPTION_ARG_NONE, &routines, "Include routines", NULL },
	{ "events", 'e', 0, G_OPTION_ARG_NONE, &events, "Include events", NULL },
	{ "table-style", 'T', 0, G_OPTION_ARG_STRING, &table_style, "Table style (USE, DROP+CREATE or CREATE)", NULL },
	{ "triggers", 't', 0, G_OPTION_ARG_NONE, &triggers, "Include triggers", NULL },
	{ "data-style", 'D', 0, G_OPTION_ARG_STRING, &data_style, "Data style (INSERT, TRUNCATE+INSERT or INSERT+UPDATE)", NULL },
	{ "zip" , 'z', 0, G_OPTION_ARG_NONE, &zip, "Compress output (gzip), only applies if output is to file (-o/--output)", NULL}
};

static void build_form_data(const gchar *table_name, GString *form_data) {
	g_string_append_printf(form_data, "data[]=%s&table[]=%s&", table_name, table_name);
}

static void dump_response(GInputStream *istream, const gchar *outfile) {
	GError *error;
	gsize len;
	gchar buffer[BUFSIZE];
	GOutputStream *os;

	error = NULL;

	if (outfile != NULL) {

		// Output to file
		GFile *file = g_file_new_for_path(outfile);
		os = G_OUTPUT_STREAM(g_file_replace(file, NULL, FALSE, G_FILE_CREATE_REPLACE_DESTINATION, NULL, &error));
		if (error) {
			g_error("%s\n", error->message);
		}

		g_output_stream_splice(os, istream, G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, &error);
		if (error) {
			g_error("%s\n", error->message);
		}

		return;
	}
	
	// Output to stdout
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


int main(int argc, char **argv) {

	SoupSession *session;
	SoupMessage *message;
	SoupCookieJar *cookiejar;
	GError *error;
	GInputStream *istream;
	gchar buffer[BUFSIZE];
	GOptionContext  *context;

	context = g_option_context_new("url");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("Option parsing failed: %s\n", error->message);
		exit(1);
	}
	if (argc < 1) {
		g_print("Missing URL\n");
		exit(1);
	}
	url = g_strdup(argv[1]);
	g_debug("url: %s", url);
	g_debug("username: %s", username);
	g_debug("password: %s", password);
	g_debug("database: %s", database);


	gchar formdata[8192];
	g_snprintf(formdata, sizeof(formdata), 
			"auth[driver]=%s&"
			"auth[server]=%s&"
			"auth[username]=%s&"
			"auth[password]=%s&"
			"auth[db]=%s",
			"server",
			"",
			username,
			password,
			database
	);
	g_debug("%s", formdata);

	session = soup_session_new();

	cookiejar = soup_cookie_jar_new();
	soup_cookie_jar_set_accept_policy(cookiejar, SOUP_COOKIE_JAR_ACCEPT_ALWAYS);
	soup_session_add_feature(session, SOUP_SESSION_FEATURE(cookiejar));
	g_object_unref(cookiejar);

	message = soup_message_new("POST", url);
	if (message == NULL) {
		g_error("URL is invalid: %s\n", url);
	}
	soup_message_set_request(message, "application/x-www-form-urlencoded", SOUP_MEMORY_COPY, formdata, strlen(formdata));

	error = NULL;
	istream = soup_session_send(session, message, NULL, &error);
	if (error != NULL) {
		g_error("%s\n", error->message);
	}

	g_debug("status: %u", message->status_code);

	if (message->status_code != 200) {
		g_error("Server returned %u\n", message->status_code);
		exit(-1);
	}

	gsize len;
	g_input_stream_read_all(istream, buffer, sizeof(buffer), &len, NULL, &error);
	if (error != NULL) {
		g_error("%s", error->message);
	}
	

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

	g_debug("%s", token);
	
	SoupMessage *message2;
	gchar *url2;
	url2 = g_strdup_printf("%s?username=%s&db=%s&dump=", url, username, database);
	g_debug("%s", url2);

	message2 = soup_message_new("GET", url2);

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
	g_string_printf(form_data, "output=%s&format=%s&db_style=%s&routines=%u&events=%u&table_style=%s&triggers=%u&data_style=%s&token=%s&",
			(output != NULL && zip) ? "gz" : "text" ,
			format,
			db_style,
			(gint)routines,
			(gint)events,
			table_style,
			(gint)triggers,
			data_style,
			token
	);
	g_debug("%s\n", form_data->str);

	g_list_foreach(tables, (GFunc)build_form_data, form_data);
	form_data = g_string_truncate(form_data, form_data->len - 1);

	SoupMessage *message3 = soup_message_new("POST", url2);
	soup_message_set_request(message3, "application/x-www-form-urlencoded", SOUP_MEMORY_COPY, form_data->str, form_data->len);
	error = NULL;
	GInputStream *is;
	is = soup_session_send(session, message3, NULL, &error);
	if (error) {
		g_error("%s\n", error->message);
	}

	dump_response(is, output);
	return 0;
}
