#include <gst/gst.h>
#include <glib-unix.h>
#include <glib/gstdio.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define MAX_PATHS 10000
#define MAX_READERS 100000

typedef struct _RunContext RunContext;

typedef struct {
    gchar *path;
    GstElement *pipeline;
    guint bus_watch_id;
    gint64 started_at_us;
    gboolean first_packet_seen;
    gboolean failed;
    RunContext *run;
} Reader;

struct _RunContext {
    GMainLoop *loop;
    GPtrArray *readers;
    FILE *events;
    GMutex lock;
    guint next_reader;
    guint started_readers;
    guint ready_readers;
    guint failed_readers;
    guint connect_rate;
    guint hold_seconds;
    gboolean allow_failures;
    gboolean stop_scheduled;
};

static gchar *server_host = NULL;
static gint server_port = 9999;
static gchar *paths_file = NULL;
static gint readers_per_path = 1;
static gint connect_rate = 10;
static gint hold_seconds = 10;
static gchar *credentials_file = NULL;
static gchar *events_file = NULL;
static gboolean allow_failures = FALSE;

static GOptionEntry entries[] = {
    {"host", 0, 0, G_OPTION_ARG_STRING, &server_host,
     "RTSP server host", "HOST"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &server_port,
     "RTSP server TCP port", "PORT"},
    {"paths-file", 0, 0, G_OPTION_ARG_FILENAME, &paths_file,
     "File with one safe RTSP path per line", "PATH"},
    {"readers-per-path", 'r', 0, G_OPTION_ARG_INT, &readers_per_path,
     "Readers to start for each path", "COUNT"},
    {"connect-rate", 0, 0, G_OPTION_ARG_INT, &connect_rate,
     "Reader starts per second; zero starts one burst", "RATE"},
    {"hold-seconds", 0, 0, G_OPTION_ARG_INT, &hold_seconds,
     "Seconds to hold after the last reader starts", "SECONDS"},
    {"credentials-file", 0, 0, G_OPTION_ARG_FILENAME, &credentials_file,
     "Optional two-line Basic Auth username/password file", "PATH"},
    {"events-file", 0, 0, G_OPTION_ARG_FILENAME, &events_file,
     "Exclusive raw JSONL event output", "PATH"},
    {"allow-failures", 0, 0, G_OPTION_ARG_NONE, &allow_failures,
     "Return success after recording expected injected failures", NULL},
    {NULL}
};

static gboolean
safe_token(const gchar *value, gsize maximum_length)
{
    const gchar *cursor;
    gsize length;

    if (value == NULL) {
        return FALSE;
    }
    length = strlen(value);
    if (length < 1 || length > maximum_length) {
        return FALSE;
    }
    for (cursor = value; *cursor != '\0'; cursor++) {
        if (!(g_ascii_isalnum(*cursor) || *cursor == '-' || *cursor == '_' ||
              *cursor == '.' || *cursor == ':')) {
            return FALSE;
        }
    }
    return TRUE;
}

static void
record_failure(Reader *reader, const gchar *reason)
{
    RunContext *run = reader->run;

    g_mutex_lock(&run->lock);
    if (!reader->failed) {
        reader->failed = TRUE;
        run->failed_readers++;
        g_fprintf(run->events,
                  "{\"event\":\"reader_error\",\"path\":\"%s\","
                  "\"reason\":\"%s\"}\n",
                  reader->path, reason);
        fflush(run->events);
    }
    g_mutex_unlock(&run->lock);
}

static void
on_handoff(GstElement *sink G_GNUC_UNUSED, GstBuffer *buffer G_GNUC_UNUSED,
           GstPad *pad G_GNUC_UNUSED, gpointer user_data)
{
    Reader *reader = user_data;
    RunContext *run = reader->run;

    g_mutex_lock(&run->lock);
    if (!reader->first_packet_seen) {
        gdouble latency_ms =
            (g_get_monotonic_time() - reader->started_at_us) / 1000.0;
        reader->first_packet_seen = TRUE;
        run->ready_readers++;
        g_fprintf(run->events,
                  "{\"event\":\"first_packet\",\"path\":\"%s\","
                  "\"latency_ms\":%.3f}\n",
                  reader->path, latency_ms);
        fflush(run->events);
    }
    g_mutex_unlock(&run->lock);
}

static gboolean
on_bus_message(GstBus *bus G_GNUC_UNUSED, GstMessage *message,
               gpointer user_data)
{
    Reader *reader = user_data;

    if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
        GError *error = NULL;
        gchar *debug = NULL;
        gst_message_parse_error(message, &error, &debug);
        record_failure(reader, "gstreamer_error");
        g_clear_error(&error);
        g_free(debug);
    } else if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_EOS) {
        record_failure(reader, "unexpected_eos");
    }
    return G_SOURCE_CONTINUE;
}

static void
free_reader(gpointer data)
{
    Reader *reader = data;
    if (reader->bus_watch_id != 0) {
        g_source_remove(reader->bus_watch_id);
    }
    gst_element_set_state(reader->pipeline, GST_STATE_NULL);
    gst_object_unref(reader->pipeline);
    g_free(reader->path);
    g_free(reader);
}

static Reader *
create_reader(RunContext *run, const gchar *path, const gchar *username,
              const gchar *password, GError **error)
{
    Reader *reader;
    gchar *url_host;
    gchar *url;
    gchar *escaped_url;
    gchar *launch;
    GstElement *source;
    GstElement *sink;
    GstBus *bus;

    url_host = strchr(server_host, ':') == NULL
                   ? g_strdup(server_host)
                   : g_strdup_printf("[%s]", server_host);
    url = g_strdup_printf("rtsp://%s:%d/%s", url_host, server_port, path);
    escaped_url = g_strescape(url, NULL);
    launch = g_strdup_printf(
        "rtspsrc name=source location=\"%s\" protocols=tcp latency=0 "
        "do-rtsp-keep-alive=true ! fakesink name=sink sync=false "
        "async=false signal-handoffs=true",
        escaped_url);

    reader = g_new0(Reader, 1);
    reader->path = g_strdup(path);
    reader->run = run;
    reader->pipeline = gst_parse_launch(launch, error);
    g_free(launch);
    g_free(escaped_url);
    g_free(url);
    g_free(url_host);
    if (reader->pipeline == NULL) {
        g_free(reader->path);
        g_free(reader);
        return NULL;
    }

    source = gst_bin_get_by_name(GST_BIN(reader->pipeline), "source");
    sink = gst_bin_get_by_name(GST_BIN(reader->pipeline), "sink");
    if (source == NULL || sink == NULL) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                            "reader_pipeline_elements_missing");
        g_clear_object(&source);
        g_clear_object(&sink);
        gst_object_unref(reader->pipeline);
        g_free(reader->path);
        g_free(reader);
        return NULL;
    }
    if (username != NULL) {
        g_object_set(source, "user-id", username, "user-pw", password, NULL);
    }
    g_signal_connect(sink, "handoff", G_CALLBACK(on_handoff), reader);
    gst_object_unref(source);
    gst_object_unref(sink);

    bus = gst_element_get_bus(reader->pipeline);
    reader->bus_watch_id = gst_bus_add_watch(bus, on_bus_message, reader);
    gst_object_unref(bus);
    return reader;
}

static gboolean
stop_run(gpointer user_data)
{
    RunContext *run = user_data;
    g_main_loop_quit(run->loop);
    return G_SOURCE_REMOVE;
}

static gboolean
start_reader_batch(gpointer user_data)
{
    RunContext *run = user_data;
    guint batch_size;
    guint batch_end;

    if (run->connect_rate == 0) {
        batch_size = run->readers->len;
    } else {
        batch_size = MAX(1U, (run->connect_rate + 9U) / 10U);
    }
    batch_end = MIN(run->next_reader + batch_size, run->readers->len);
    while (run->next_reader < batch_end) {
        Reader *reader = g_ptr_array_index(run->readers, run->next_reader);
        GstStateChangeReturn state_change;

        reader->started_at_us = g_get_monotonic_time();
        state_change = gst_element_set_state(reader->pipeline, GST_STATE_PLAYING);
        run->started_readers++;
        if (state_change == GST_STATE_CHANGE_FAILURE) {
            record_failure(reader, "state_change_failure");
        }
        run->next_reader++;
    }
    if (run->next_reader == run->readers->len) {
        if (!run->stop_scheduled) {
            run->stop_scheduled = TRUE;
            g_timeout_add_seconds(run->hold_seconds, stop_run, run);
        }
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static gboolean
read_credentials(gchar **username, gchar **password, GError **error)
{
    gchar *contents = NULL;
    gchar **lines;

    *username = NULL;
    *password = NULL;
    if (credentials_file == NULL) {
        return TRUE;
    }
    if (!g_path_is_absolute(credentials_file) ||
        !g_file_get_contents(credentials_file, &contents, NULL, error)) {
        return FALSE;
    }
    g_strchomp(contents);
    lines = g_strsplit(contents, "\n", 3);
    if (lines[0] == NULL || lines[1] == NULL || lines[2] != NULL ||
        lines[0][0] == '\0' || lines[1][0] == '\0') {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "credentials_file_must_have_two_nonempty_lines");
        g_strfreev(lines);
        g_free(contents);
        return FALSE;
    }
    *username = g_strdup(lines[0]);
    *password = g_strdup(lines[1]);
    g_strfreev(lines);
    g_free(contents);
    return TRUE;
}

static GPtrArray *
read_paths(GError **error)
{
    gchar *contents = NULL;
    gchar **lines;
    GHashTable *seen;
    GPtrArray *paths;
    guint index;

    if (paths_file == NULL || !g_path_is_absolute(paths_file) ||
        !g_file_get_contents(paths_file, &contents, NULL, error)) {
        return NULL;
    }
    lines = g_strsplit(contents, "\n", -1);
    seen = g_hash_table_new(g_str_hash, g_str_equal);
    paths = g_ptr_array_new_with_free_func(g_free);
    for (index = 0; lines[index] != NULL; index++) {
        if (lines[index][0] == '\0') {
            continue;
        }
        if (!safe_token(lines[index], 128) ||
            g_hash_table_contains(seen, lines[index])) {
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "paths_file_contains_invalid_or_duplicate_path");
            g_ptr_array_unref(paths);
            paths = NULL;
            break;
        }
        g_hash_table_add(seen, lines[index]);
        g_ptr_array_add(paths, g_strdup(lines[index]));
        if (paths->len > MAX_PATHS) {
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "paths_file_exceeds_limit");
            g_ptr_array_unref(paths);
            paths = NULL;
            break;
        }
    }
    g_hash_table_unref(seen);
    g_strfreev(lines);
    g_free(contents);
    if (paths != NULL && paths->len == 0) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "paths_file_is_empty");
        g_ptr_array_unref(paths);
        return NULL;
    }
    return paths;
}

int
main(int argc, char *argv[])
{
    GOptionContext *option_context;
    GError *error = NULL;
    GPtrArray *paths = NULL;
    gchar *username = NULL;
    gchar *password = NULL;
    RunContext run = {0};
    guint path_index;
    gint reader_index;
    gint exit_code;

    option_context = g_option_context_new("- scalable GStreamer RTSP/TCP readers");
    g_option_context_add_main_entries(option_context, entries, NULL);
    g_option_context_add_group(option_context, gst_init_get_option_group());
    if (!g_option_context_parse(option_context, &argc, &argv, &error)) {
        g_printerr("option_error: %s\n", error->message);
        g_clear_error(&error);
        g_option_context_free(option_context);
        return 2;
    }
    g_option_context_free(option_context);

    if (!safe_token(server_host, 253) || server_port < 1 || server_port > 65535 ||
        readers_per_path < 1 || connect_rate < 0 || connect_rate > 10000 ||
        hold_seconds < 1 || hold_seconds > 172800 || events_file == NULL ||
        !g_path_is_absolute(events_file)) {
        g_printerr("configuration_error: invalid_reader_configuration\n");
        return 2;
    }
    paths = read_paths(&error);
    if (paths == NULL ||
        paths->len > (guint) (MAX_READERS / readers_per_path) ||
        !read_credentials(&username, &password, &error)) {
        g_printerr("configuration_error: %s\n",
                   error == NULL ? "reader_count_exceeds_limit" : error->message);
        g_clear_error(&error);
        g_clear_pointer(&paths, g_ptr_array_unref);
        g_free(username);
        g_free(password);
        return 2;
    }

    run.events = g_fopen(events_file, "wx");
    if (run.events == NULL) {
        g_printerr("events_error: unable_to_create_exclusive_output\n");
        g_ptr_array_unref(paths);
        g_free(username);
        g_free(password);
        return 2;
    }
    g_chmod(events_file, 0640);
    run.loop = g_main_loop_new(NULL, FALSE);
    run.readers = g_ptr_array_new_with_free_func(free_reader);
    run.connect_rate = (guint) connect_rate;
    run.hold_seconds = (guint) hold_seconds;
    run.allow_failures = allow_failures;
    g_mutex_init(&run.lock);

    for (path_index = 0; path_index < paths->len; path_index++) {
        const gchar *path = g_ptr_array_index(paths, path_index);
        for (reader_index = 0; reader_index < readers_per_path; reader_index++) {
            Reader *reader = create_reader(&run, path, username, password, &error);
            if (reader == NULL) {
                g_printerr("pipeline_error: %s\n", error->message);
                g_clear_error(&error);
                g_ptr_array_unref(paths);
                g_ptr_array_unref(run.readers);
                g_main_loop_unref(run.loop);
                g_mutex_clear(&run.lock);
                fclose(run.events);
                g_free(username);
                g_free(password);
                return 3;
            }
            g_ptr_array_add(run.readers, reader);
        }
    }
    g_ptr_array_unref(paths);
    g_free(username);
    g_free(password);

    g_unix_signal_add(SIGINT, stop_run, &run);
    g_unix_signal_add(SIGTERM, stop_run, &run);
    if (run.connect_rate == 0) {
        g_idle_add(start_reader_batch, &run);
    } else {
        g_timeout_add(100, start_reader_batch, &run);
    }
    g_main_loop_run(run.loop);

    g_print("SUMMARY started=%u first_packet=%u failed=%u transport=tcp\n",
            run.started_readers, run.ready_readers, run.failed_readers);
    exit_code =
        run.allow_failures || (run.ready_readers == run.started_readers &&
                               run.failed_readers == 0)
            ? 0
            : 5;
    g_ptr_array_unref(run.readers);
    g_main_loop_unref(run.loop);
    g_mutex_clear(&run.lock);
    fclose(run.events);
    g_free(server_host);
    g_free(paths_file);
    g_free(credentials_file);
    g_free(events_file);
    return exit_code;
}
