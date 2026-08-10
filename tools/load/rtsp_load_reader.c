#define _GNU_SOURCE

#include <gst/gst.h>
#include <gst/rtsp/gstrtspmessage.h>
#include <glib-unix.h>
#include <glib/gstdio.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#define MAX_PATHS 10000
#define MAX_READERS 100000
#define MAX_SECRET_BYTES 8192

typedef struct _RunContext RunContext;

typedef struct {
    guint id;
    gchar *path;
    GstElement *pipeline;
    guint bus_watch_id;
    guint reconnect_source_id;
    guint cycle;
    guint failure_retries;
    gint64 describe_at_us;
    gint64 play_at_us;
    volatile gint decodable_seen;
    gboolean ever_decodable;
    gboolean failed_cycle;
    volatile gint connected;
    volatile gint outage_member;
    volatile gint outage_recovered;
    guint64 rtp_packets;
    RunContext *run;
} Reader;

typedef struct {
    gchar *path;
    guint reader_count;
    guint reader_id_start;
} PlanTarget;

struct _RunContext {
    GMainLoop *loop;
    GPtrArray *readers;
    FILE *events;
    GMutex lock;
    gint64 epoch_us;
    guint next_reader;
    guint started_readers;
    guint started_attempts;
    guint ready_readers;
    guint decodable_attempts;
    guint failed_attempts;
    guint connect_rate;
    guint hold_seconds;
    guint disconnect_rate;
    guint reconnect_attempts;
    guint backoff_base_ms;
    guint backoff_max_ms;
    guint outage_percent;
    guint seed;
    guint schedule_shards;
    guint schedule_shard_index;
    guint global_reader_count;
    guint start_source_id;
    guint stop_source_id;
    guint lifecycle_source_id;
    guint steady_cursor;
    guint injected_disconnects;
    gint64 next_disconnect_us;
    gint64 stop_deadline_us;
    gboolean allow_failures;
    gboolean normal_completion;
    gboolean interrupted;
    gboolean outage_injected;
    gboolean lifecycle_started;
    volatile gint stopping;
    gint64 scheduled_start_unix_ms;
    gint64 process_start_unix_ms;
    gboolean clock_synchronized;
    gdouble clock_max_error_ms;
    const gchar *lifecycle;
};

static gchar *server_host = NULL;
static gint server_port = 9999;
static gchar *reader_plan_file = NULL;
static gchar *codec = NULL;
static gint connect_rate = 10;
static gint hold_seconds = 10;
static gchar *credentials_file = NULL;
static gchar *events_file = NULL;
static gchar *lifecycle = NULL;
static gint disconnect_rate = 0;
static gint reconnect_attempts = 0;
static gint backoff_base_ms = 250;
static gint backoff_max_ms = 30000;
static gint outage_percent = 0;
static gint scenario_seed = 0;
static gint schedule_shards = 1;
static gint schedule_shard_index = 0;
static gint global_reader_count = 0;
static gchar *generator_host = NULL;
static gchar *profile_sha256 = NULL;
static gchar *reader_plan_sha256 = NULL;
static gint64 start_unix_ms = 0;
static gboolean allow_failures = FALSE;

static GOptionEntry entries[] = {
    {"host", 0, 0, G_OPTION_ARG_STRING, &server_host,
     "RTSP server host", "HOST"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &server_port,
     "RTSP server TCP port", "PORT"},
    {"reader-plan", 0, 0, G_OPTION_ARG_FILENAME, &reader_plan_file,
     "TSV path, reader count and first reader id", "PATH"},
    {"codec", 0, 0, G_OPTION_ARG_STRING, &codec,
     "Video codec used by the prepared fixture: h264 or h265", "CODEC"},
    {"connect-rate", 0, 0, G_OPTION_ARG_INT, &connect_rate,
     "Maximum initial reader starts per second; zero starts one burst", "RATE"},
    {"hold-seconds", 0, 0, G_OPTION_ARG_INT, &hold_seconds,
     "Seconds to hold after the last initial reader starts", "SECONDS"},
    {"credentials-file", 0, 0, G_OPTION_ARG_FILENAME, &credentials_file,
     "Optional owner-only two-line Basic Auth username/password file", "PATH"},
    {"events-file", 0, 0, G_OPTION_ARG_FILENAME, &events_file,
     "Exclusive raw JSONL event output", "PATH"},
    {"lifecycle", 0, 0, G_OPTION_ARG_STRING, &lifecycle,
     "single, steady, ramp, burst or outage", "MODE"},
    {"disconnect-rate", 0, 0, G_OPTION_ARG_INT, &disconnect_rate,
     "Injected steady disconnects per second", "RATE"},
    {"reconnect-attempts", 0, 0, G_OPTION_ARG_INT, &reconnect_attempts,
     "Retries after an unexpected reader failure", "COUNT"},
    {"backoff-base-ms", 0, 0, G_OPTION_ARG_INT, &backoff_base_ms,
     "Minimum reconnect backoff", "MILLISECONDS"},
    {"backoff-max-ms", 0, 0, G_OPTION_ARG_INT, &backoff_max_ms,
     "Maximum reconnect backoff and outage jitter window", "MILLISECONDS"},
    {"outage-percent", 0, 0, G_OPTION_ARG_INT, &outage_percent,
     "Exact injected outage cohort: 0, 10, 25 or 100", "PERCENT"},
    {"seed", 0, 0, G_OPTION_ARG_INT, &scenario_seed,
     "Deterministic lifecycle seed", "SEED"},
    {"schedule-shards", 0, 0, G_OPTION_ARG_INT, &schedule_shards,
     "Number of coordinated reader processes", "COUNT"},
    {"schedule-shard-index", 0, 0, G_OPTION_ARG_INT, &schedule_shard_index,
     "Zero-based coordinated reader process index", "INDEX"},
    {"global-reader-count", 0, 0, G_OPTION_ARG_INT, &global_reader_count,
     "Readers across all coordinated processes", "COUNT"},
    {"generator-host", 0, 0, G_OPTION_ARG_STRING, &generator_host,
     "Generator host identity bound by the launch plan", "NAME"},
    {"profile-sha256", 0, 0, G_OPTION_ARG_STRING, &profile_sha256,
     "Canonical load profile digest", "SHA256"},
    {"reader-plan-sha256", 0, 0, G_OPTION_ARG_STRING, &reader_plan_sha256,
     "Reader plan digest", "SHA256"},
    {"start-unix-ms", 0, 0, G_OPTION_ARG_INT64, &start_unix_ms,
     "Common future realtime start epoch in milliseconds", "MILLISECONDS"},
    {"allow-failures", 0, 0, G_OPTION_ARG_NONE, &allow_failures,
     "Allow recorded failures only after a complete non-interrupted run", NULL},
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
wipe_and_free(gchar *value)
{
    volatile gchar *cursor;
    gsize length;

    if (value == NULL) {
        return;
    }
    length = strlen(value);
    cursor = (volatile gchar *) value;
    while (length > 0) {
        cursor[--length] = '\0';
    }
    g_free(value);
}

static gdouble
event_time_ms(RunContext *run)
{
    return (g_get_monotonic_time() - run->epoch_us) / 1000.0;
}

static gint64
unix_time_ms(void)
{
    return g_get_real_time() / 1000;
}

static gboolean
safe_sha256(const gchar *value)
{
    guint index;
    if (value == NULL || strlen(value) != 64) {
        return FALSE;
    }
    for (index = 0; index < 64; index++) {
        if (!g_ascii_isxdigit(value[index]) || g_ascii_isupper(value[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static void
record_reader_started(Reader *reader)
{
    RunContext *run = reader->run;
    g_fprintf(run->events,
              "{\"event\":\"reader_started\",\"reader_id\":%u,"
              "\"cycle\":%u,\"path\":\"%s\","
              "\"at_monotonic_ms\":%.3f,\"at_unix_ms\":%" G_GINT64_FORMAT "}\n",
              reader->id, reader->cycle, reader->path, event_time_ms(run),
              unix_time_ms());
    fflush(run->events);
}

static guint
deterministic_jitter(Reader *reader, guint range)
{
    guint value = reader->run->seed ^ (reader->id * 2654435761U) ^
                  (reader->cycle * 2246822519U);
    value ^= value >> 16;
    value *= 2246822519U;
    value ^= value >> 13;
    return range == 0 ? 0 : value % range;
}

static gboolean reconnect_reader(gpointer user_data);

static void
schedule_reconnect(Reader *reader, gboolean spread_across_full_window)
{
    RunContext *run = reader->run;
    guint delay_ms;
    guint range;

    if (reader->reconnect_source_id != 0 || run->normal_completion ||
        run->interrupted) {
        return;
    }
    if (spread_across_full_window) {
        range = run->backoff_max_ms - run->backoff_base_ms + 1U;
        delay_ms = run->backoff_base_ms + deterministic_jitter(reader, range);
    } else {
        guint exponent = MIN(reader->failure_retries, 16U);
        guint64 ceiling = (guint64) run->backoff_base_ms << exponent;
        guint bounded = (guint) MIN(ceiling, (guint64) run->backoff_max_ms);
        delay_ms = run->backoff_base_ms +
                   deterministic_jitter(reader, bounded - run->backoff_base_ms + 1U);
    }
    g_mutex_lock(&run->lock);
    g_fprintf(run->events,
              "{\"event\":\"reconnect_scheduled\",\"reader_id\":%u,"
              "\"cycle\":%u,\"path\":\"%s\","
              "\"at_monotonic_ms\":%.3f,\"backoff_ms\":%u}\n",
              reader->id, reader->cycle, reader->path, event_time_ms(run),
              delay_ms);
    fflush(run->events);
    g_mutex_unlock(&run->lock);
    reader->reconnect_source_id =
        g_timeout_add(MAX(delay_ms, 1U), reconnect_reader, reader);
}

static void
record_failure(Reader *reader, const gchar *reason)
{
    RunContext *run = reader->run;
    gboolean should_retry = FALSE;

    g_mutex_lock(&run->lock);
    if (!reader->failed_cycle) {
        reader->failed_cycle = TRUE;
        g_atomic_int_set(&reader->connected, FALSE);
        run->failed_attempts++;
        g_fprintf(run->events,
                  "{\"event\":\"reader_error\",\"reader_id\":%u,"
                  "\"cycle\":%u,\"path\":\"%s\","
                  "\"at_monotonic_ms\":%.3f,\"reason\":\"%s\"}\n",
                  reader->id, reader->cycle, reader->path, event_time_ms(run),
                  reason);
        fflush(run->events);
        if (reader->failure_retries < run->reconnect_attempts) {
            reader->failure_retries++;
            should_retry = TRUE;
        }
    }
    g_mutex_unlock(&run->lock);
    if (should_retry) {
        gst_element_set_state(reader->pipeline, GST_STATE_NULL);
        schedule_reconnect(reader, FALSE);
    }
}

static gboolean
on_before_send(GstElement *source G_GNUC_UNUSED, GstRTSPMessage *message,
               gpointer user_data)
{
    Reader *reader = user_data;
    RunContext *run = reader->run;
    GstRTSPMethod method;
    const gchar *uri;
    GstRTSPVersion version;
    gint64 now;

    if (gst_rtsp_message_get_type(message) != GST_RTSP_MESSAGE_REQUEST ||
        gst_rtsp_message_parse_request(message, &method, &uri, &version) !=
            GST_RTSP_OK) {
        return TRUE;
    }
    (void) uri;
    (void) version;
    now = g_get_monotonic_time();
    g_mutex_lock(&run->lock);
    if (method == GST_RTSP_DESCRIBE && reader->describe_at_us == 0) {
        reader->describe_at_us = now;
    } else if (method == GST_RTSP_PLAY && reader->play_at_us == 0 &&
               reader->describe_at_us != 0) {
        reader->play_at_us = now;
        g_fprintf(run->events,
                  "{\"event\":\"play_sent\",\"reader_id\":%u,"
                  "\"cycle\":%u,\"path\":\"%s\","
                  "\"at_monotonic_ms\":%.3f,"
                  "\"describe_to_play_ms\":%.3f}\n",
                  reader->id, reader->cycle, reader->path, event_time_ms(run),
                  (reader->play_at_us - reader->describe_at_us) / 1000.0);
        fflush(run->events);
    }
    g_mutex_unlock(&run->lock);
    return TRUE;
}

static gboolean inject_outage(gpointer user_data);
static gboolean steady_disconnect(gpointer user_data);

static void
start_lifecycle_if_ready(RunContext *run)
{
    if (run->lifecycle_started || run->ready_readers != run->readers->len) {
        return;
    }
    run->lifecycle_started = TRUE;
    if (g_str_equal(run->lifecycle, "outage")) {
        run->lifecycle_source_id = g_timeout_add_seconds(1, inject_outage, run);
    } else if (g_str_equal(run->lifecycle, "steady")) {
        guint64 offset_us =
            ((guint64) run->schedule_shard_index * G_USEC_PER_SEC) /
            run->disconnect_rate;
        run->next_disconnect_us = g_get_monotonic_time() + (gint64) offset_us;
        run->lifecycle_source_id = g_timeout_add(
            MAX(1U, (guint) ((offset_us + 999U) / 1000U)),
            steady_disconnect, run);
    }
}

typedef struct {
    Reader *reader;
    gint64 observed_at_us;
} DecodableNotice;

static gboolean
process_decodable(gpointer user_data)
{
    DecodableNotice *notice = user_data;
    Reader *reader = notice->reader;
    RunContext *run = reader->run;
    gint64 now = notice->observed_at_us;

    if (g_atomic_int_get(&run->stopping)) {
        g_free(notice);
        return G_SOURCE_REMOVE;
    }
    g_mutex_lock(&run->lock);
    if (reader->describe_at_us == 0 || reader->play_at_us == 0) {
        g_atomic_int_set(&reader->decodable_seen, FALSE);
        g_mutex_unlock(&run->lock);
        record_failure(reader, "state_change_failure");
        g_free(notice);
        return G_SOURCE_REMOVE;
    }
    g_atomic_int_set(&reader->connected, TRUE);
    run->decodable_attempts++;
    if (!reader->ever_decodable) {
        reader->ever_decodable = TRUE;
        run->ready_readers++;
    }
    if (g_atomic_int_get(&reader->outage_member) && reader->cycle > 0) {
        g_atomic_int_set(&reader->outage_recovered, TRUE);
    }
    reader->failure_retries = 0;
    g_fprintf(run->events,
              "{\"event\":\"first_decodable_frame\","
              "\"reader_id\":%u,\"cycle\":%u,\"path\":\"%s\","
              "\"at_monotonic_ms\":%.3f,"
              "\"describe_to_first_decodable_ms\":%.3f,"
              "\"play_to_first_decodable_ms\":%.3f}\n",
              reader->id, reader->cycle, reader->path, event_time_ms(run),
              (now - reader->describe_at_us) / 1000.0,
              (now - reader->play_at_us) / 1000.0);
    fflush(run->events);
    start_lifecycle_if_ready(run);
    g_mutex_unlock(&run->lock);
    g_free(notice);
    return G_SOURCE_REMOVE;
}

static void
on_handoff(GstElement *sink G_GNUC_UNUSED, GstBuffer *buffer,
           GstPad *pad G_GNUC_UNUSED, gpointer user_data)
{
    Reader *reader = user_data;
    RunContext *run = reader->run;
    DecodableNotice *notice;

    if (g_atomic_int_get(&run->stopping)) {
        return;
    }
    if (GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT) ||
        !g_atomic_int_compare_and_exchange(&reader->decodable_seen, FALSE, TRUE)) {
        return;
    }
    notice = g_new0(DecodableNotice, 1);
    notice->reader = reader;
    notice->observed_at_us = g_get_monotonic_time();
    g_main_context_invoke(NULL, process_decodable, notice);
}

static GstPadProbeReturn
count_rtp_packet(GstPad *pad G_GNUC_UNUSED, GstPadProbeInfo *info,
                 gpointer user_data)
{
    Reader *reader = user_data;
    if ((GST_PAD_PROBE_INFO_TYPE(info) & GST_PAD_PROBE_TYPE_BUFFER) != 0) {
        reader->rtp_packets++;
    }
    return GST_PAD_PROBE_OK;
}

static void
on_source_pad_added(GstElement *source G_GNUC_UNUSED, GstPad *pad,
                    gpointer user_data)
{
    gst_pad_add_probe(pad, GST_PAD_PROBE_TYPE_BUFFER, count_rtp_packet,
                      user_data, NULL);
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
    } else if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_EOS &&
               g_atomic_int_get(&reader->connected)) {
        record_failure(reader, "unexpected_eos");
    }
    return G_SOURCE_CONTINUE;
}

static void
free_reader(gpointer data)
{
    Reader *reader = data;
    if (reader->reconnect_source_id != 0) {
        g_source_remove(reader->reconnect_source_id);
    }
    if (reader->bus_watch_id != 0) {
        g_source_remove(reader->bus_watch_id);
    }
    gst_element_set_state(reader->pipeline, GST_STATE_NULL);
    gst_object_unref(reader->pipeline);
    g_free(reader->path);
    g_free(reader);
}

static Reader *
create_reader(RunContext *run, guint reader_id, const gchar *path,
              const gchar *username, const gchar *password, GError **error)
{
    Reader *reader;
    gchar *url_host;
    gchar *url;
    gchar *escaped_url;
    gchar *launch;
    const gchar *depay;
    const gchar *parser;
    GstElement *source;
    GstElement *sink;
    GstBus *bus;

    depay = g_str_equal(codec, "h264") ? "rtph264depay" : "rtph265depay";
    parser = g_str_equal(codec, "h264") ? "h264parse" : "h265parse";
    url_host = strchr(server_host, ':') == NULL
                   ? g_strdup(server_host)
                   : g_strdup_printf("[%s]", server_host);
    url = g_strdup_printf("rtsp://%s:%d/%s", url_host, server_port, path);
    escaped_url = g_strescape(url, NULL);
    launch = g_strdup_printf(
        "rtspsrc name=source location=\"%s\" protocols=tcp latency=0 "
        "do-rtsp-keep-alive=true ! %s ! %s ! "
        "fakesink name=sink sync=false async=false signal-handoffs=true",
        escaped_url, depay, parser);

    reader = g_new0(Reader, 1);
    reader->id = reader_id;
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
    g_signal_connect(source, "before-send", G_CALLBACK(on_before_send), reader);
    g_signal_connect(source, "pad-added", G_CALLBACK(on_source_pad_added), reader);
    g_signal_connect(sink, "handoff", G_CALLBACK(on_handoff), reader);
    gst_object_unref(source);
    gst_object_unref(sink);

    bus = gst_element_get_bus(reader->pipeline);
    reader->bus_watch_id = gst_bus_add_watch(bus, on_bus_message, reader);
    gst_object_unref(bus);
    return reader;
}

static gboolean
stop_run_normal(gpointer user_data)
{
    RunContext *run = user_data;
    run->stop_source_id = 0;
    run->normal_completion = TRUE;
    g_main_loop_quit(run->loop);
    return G_SOURCE_REMOVE;
}

static gboolean
interrupt_run(gpointer user_data)
{
    RunContext *run = user_data;
    run->interrupted = TRUE;
    g_main_loop_quit(run->loop);
    return G_SOURCE_CONTINUE;
}

static void
start_reader(Reader *reader)
{
    RunContext *run = reader->run;
    GstStateChangeReturn state_change;

    reader->describe_at_us = 0;
    reader->play_at_us = 0;
    reader->failed_cycle = FALSE;
    g_atomic_int_set(&reader->connected, FALSE);
    g_atomic_int_set(&reader->decodable_seen, FALSE);
    g_mutex_lock(&run->lock);
    record_reader_started(reader);
    run->started_attempts++;
    g_mutex_unlock(&run->lock);
    state_change = gst_element_set_state(reader->pipeline, GST_STATE_PLAYING);
    if (state_change == GST_STATE_CHANGE_FAILURE) {
        record_failure(reader, "state_change_failure");
    }
}

static gboolean
reconnect_reader(gpointer user_data)
{
    Reader *reader = user_data;
    reader->reconnect_source_id = 0;
    reader->cycle++;
    start_reader(reader);
    return G_SOURCE_REMOVE;
}

static void
finish_initial_start(RunContext *run)
{
    if (run->stop_source_id == 0) {
        run->stop_deadline_us =
            g_get_monotonic_time() + ((gint64) run->hold_seconds * G_USEC_PER_SEC);
        run->stop_source_id =
            g_timeout_add_seconds(run->hold_seconds, stop_run_normal, run);
    }
}

static gboolean schedule_next_reader(gpointer user_data);

static gboolean
start_next_reader(gpointer user_data)
{
    RunContext *run = user_data;
    Reader *reader;

    run->start_source_id = 0;
    if (run->next_reader >= run->readers->len) {
        finish_initial_start(run);
        return G_SOURCE_REMOVE;
    }
    reader = g_ptr_array_index(run->readers, run->next_reader++);
    start_reader(reader);
    run->started_readers++;
    if (run->next_reader >= run->readers->len) {
        finish_initial_start(run);
        return G_SOURCE_REMOVE;
    }
    return schedule_next_reader(run);
}

static gboolean
schedule_next_reader(gpointer user_data)
{
    RunContext *run = user_data;
    gint64 now;
    gint64 interval_us;
    gint64 delay_us;
    Reader *next_reader;

    if (run->connect_rate == 0) {
        while (run->next_reader < run->readers->len) {
            Reader *reader = g_ptr_array_index(run->readers, run->next_reader++);
            start_reader(reader);
            run->started_readers++;
        }
        finish_initial_start(run);
        return G_SOURCE_REMOVE;
    }
    now = g_get_monotonic_time();
    interval_us = G_USEC_PER_SEC / run->connect_rate;
    next_reader = g_ptr_array_index(run->readers, run->next_reader);
    delay_us = MAX(
        0,
        run->epoch_us + ((gint64) next_reader->id * interval_us) - now);
    run->start_source_id =
        g_timeout_add(MAX(1U, (guint) ((delay_us + 999) / 1000)),
                      start_next_reader, run);
    return G_SOURCE_REMOVE;
}

static void
disconnect_for_lifecycle(Reader *reader, gboolean full_window)
{
    RunContext *run = reader->run;
    if (!g_atomic_int_get(&reader->connected) || reader->reconnect_source_id != 0) {
        return;
    }
    g_atomic_int_set(&reader->connected, FALSE);
    run->injected_disconnects++;
    g_mutex_lock(&run->lock);
    g_fprintf(run->events,
              "{\"event\":\"reader_disconnected\",\"reader_id\":%u,"
              "\"cycle\":%u,\"path\":\"%s\","
              "\"at_monotonic_ms\":%.3f,\"injected\":true}\n",
              reader->id, reader->cycle, reader->path, event_time_ms(run));
    fflush(run->events);
    g_mutex_unlock(&run->lock);
    gst_element_set_state(reader->pipeline, GST_STATE_NULL);
    schedule_reconnect(reader, full_window);
}

static gboolean
steady_disconnect(gpointer user_data)
{
    RunContext *run = user_data;
    guint examined = 0;
    gint64 now = g_get_monotonic_time();
    gint64 interval_us =
        ((gint64) G_USEC_PER_SEC * run->schedule_shards) /
        run->disconnect_rate;
    gint64 delay_us;

    run->lifecycle_source_id = 0;
    if (now + ((gint64) run->backoff_max_ms * 1000) >= run->stop_deadline_us) {
        return G_SOURCE_REMOVE;
    }
    while (examined < run->readers->len) {
        Reader *reader =
            g_ptr_array_index(run->readers, run->steady_cursor % run->readers->len);
        run->steady_cursor++;
        examined++;
        if (g_atomic_int_get(&reader->connected) && reader->reconnect_source_id == 0) {
            disconnect_for_lifecycle(reader, FALSE);
            break;
        }
    }
    run->next_disconnect_us =
        MAX(run->next_disconnect_us + interval_us, now + interval_us);
    delay_us = MAX(0, run->next_disconnect_us - now);
    run->lifecycle_source_id =
        g_timeout_add(MAX(1U, (guint) ((delay_us + 999) / 1000)),
                      steady_disconnect, run);
    return G_SOURCE_REMOVE;
}

static gboolean
inject_outage(gpointer user_data)
{
    RunContext *run = user_data;
    guint count;
    guint start;
    guint index;

    run->lifecycle_source_id = 0;
    run->outage_injected = TRUE;
    count = (run->global_reader_count * run->outage_percent + 99U) / 100U;
    start = run->seed % run->global_reader_count;
    for (index = 0; index < run->readers->len; index++) {
        Reader *reader = g_ptr_array_index(run->readers, index);
        guint distance =
            (reader->id + run->global_reader_count - start) %
            run->global_reader_count;
        if (distance < count) {
            g_atomic_int_set(&reader->outage_member, TRUE);
            disconnect_for_lifecycle(reader, TRUE);
        }
    }
    return G_SOURCE_REMOVE;
}

static gboolean
read_credentials(gchar **username, gchar **password, GError **error)
{
    gint descriptor;
    struct stat metadata;
    gchar *contents;
    ssize_t received;
    gchar **lines;

    *username = NULL;
    *password = NULL;
    if (credentials_file == NULL) {
        return TRUE;
    }
    if (!g_path_is_absolute(credentials_file)) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "credentials_file_must_be_absolute");
        return FALSE;
    }
    descriptor = open(credentials_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        !((metadata.st_mode & 0777) == 0600 ||
          (metadata.st_mode & 0777) == 0400) || metadata.st_size < 3 ||
        metadata.st_size > MAX_SECRET_BYTES) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "credentials_file_security_policy_failed");
        return FALSE;
    }
    contents = g_malloc((gsize) metadata.st_size + 1U);
    received = read(descriptor, contents, (gsize) metadata.st_size);
    close(descriptor);
    if (received != metadata.st_size) {
        wipe_and_free(contents);
        g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                            "credentials_file_read_failed");
        return FALSE;
    }
    contents[metadata.st_size] = '\0';
    g_strchomp(contents);
    lines = g_strsplit(contents, "\n", 3);
    if (lines[0] == NULL || lines[1] == NULL || lines[2] != NULL ||
        lines[0][0] == '\0' || lines[1][0] == '\0') {
        g_strfreev(lines);
        wipe_and_free(contents);
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "credentials_file_must_have_two_nonempty_lines");
        return FALSE;
    }
    *username = g_strdup(lines[0]);
    *password = g_strdup(lines[1]);
    g_strfreev(lines);
    wipe_and_free(contents);
    return TRUE;
}

static void
free_plan_target(gpointer data)
{
    PlanTarget *target = data;
    g_free(target->path);
    g_free(target);
}

static GPtrArray *
read_plan(GError **error)
{
    gchar *contents = NULL;
    gchar **lines;
    GHashTable *seen_paths;
    gboolean *seen_ids;
    GPtrArray *targets;
    guint line_index;
    guint total_readers = 0;

    if (reader_plan_file == NULL || !g_path_is_absolute(reader_plan_file) ||
        !g_file_get_contents(reader_plan_file, &contents, NULL, error)) {
        return NULL;
    }
    {
        gchar *observed_digest = g_compute_checksum_for_string(
            G_CHECKSUM_SHA256, contents, -1);
        if (!g_str_equal(observed_digest, reader_plan_sha256)) {
            g_free(observed_digest);
            g_free(contents);
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "reader_plan_digest_mismatch");
            return NULL;
        }
        g_free(observed_digest);
    }
    lines = g_strsplit(contents, "\n", -1);
    seen_paths = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    seen_ids = g_new0(gboolean, MAX_READERS);
    targets = g_ptr_array_new_with_free_func(free_plan_target);
    for (line_index = 0; lines[line_index] != NULL; line_index++) {
        gchar **fields;
        gchar *count_end = NULL;
        gchar *start_end = NULL;
        gsize field_count;
        guint64 count;
        guint64 start;
        guint offset;
        PlanTarget *target;

        if (lines[line_index][0] == '\0') {
            continue;
        }
        fields = g_strsplit(lines[line_index], "\t", 4);
        field_count = g_strv_length(fields);
        if (field_count != 3) {
            g_strfreev(fields);
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "reader_plan_contains_invalid_target");
            g_ptr_array_unref(targets);
            targets = NULL;
            break;
        }
        count = g_ascii_strtoull(fields[1], &count_end, 10);
        start = g_ascii_strtoull(fields[2], &start_end, 10);
        if (!safe_token(fields[0], 128) || count < 1 ||
            count > MAX_READERS || start >= MAX_READERS ||
            start + count > MAX_READERS || *count_end != '\0' ||
            *start_end != '\0' ||
            g_hash_table_contains(seen_paths, fields[0])) {
            g_strfreev(fields);
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "reader_plan_contains_invalid_target");
            g_ptr_array_unref(targets);
            targets = NULL;
            break;
        }
        for (offset = 0; offset < count; offset++) {
            if (seen_ids[start + offset]) {
                g_strfreev(fields);
                g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                    "reader_plan_contains_duplicate_id");
                g_ptr_array_unref(targets);
                targets = NULL;
                goto finish;
            }
            seen_ids[start + offset] = TRUE;
        }
        total_readers += (guint) count;
        g_hash_table_add(seen_paths, g_strdup(fields[0]));
        target = g_new0(PlanTarget, 1);
        target->path = g_strdup(fields[0]);
        target->reader_count = (guint) count;
        target->reader_id_start = (guint) start;
        g_ptr_array_add(targets, target);
        g_strfreev(fields);
        if (targets->len > MAX_PATHS || total_readers > MAX_READERS) {
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "reader_plan_exceeds_limit");
            g_ptr_array_unref(targets);
            targets = NULL;
            break;
        }
    }
finish:
    g_free(seen_ids);
    g_hash_table_unref(seen_paths);
    g_strfreev(lines);
    g_free(contents);
    if (targets != NULL && (targets->len == 0 || total_readers == 0)) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "reader_plan_is_empty");
        g_ptr_array_unref(targets);
        return NULL;
    }
    return targets;
}

static gboolean
valid_lifecycle_configuration(void)
{
    if (lifecycle == NULL ||
        !(g_str_equal(lifecycle, "single") || g_str_equal(lifecycle, "steady") ||
          g_str_equal(lifecycle, "ramp") || g_str_equal(lifecycle, "burst") ||
          g_str_equal(lifecycle, "outage")) ||
        disconnect_rate < 0 || disconnect_rate > 100 || reconnect_attempts < 0 ||
        reconnect_attempts > 100 || backoff_base_ms < 1 ||
        backoff_max_ms < backoff_base_ms || backoff_max_ms > 300000 ||
        !(outage_percent == 0 || outage_percent == 10 || outage_percent == 25 ||
          outage_percent == 100) || scenario_seed < 0 || schedule_shards < 1 ||
        schedule_shard_index < 0 || schedule_shard_index >= schedule_shards ||
        global_reader_count < 1 || global_reader_count > MAX_READERS) {
        return FALSE;
    }
    if (g_str_equal(lifecycle, "single")) {
        return disconnect_rate == 0 && reconnect_attempts == 0 && outage_percent == 0;
    }
    if (g_str_equal(lifecycle, "steady")) {
        return (disconnect_rate == 10 || disconnect_rate == 100) &&
               connect_rate == disconnect_rate && reconnect_attempts > 0 &&
               outage_percent == 0;
    }
    if (g_str_equal(lifecycle, "ramp")) {
        return connect_rate == 100 && disconnect_rate == 0 &&
               reconnect_attempts == 0 && outage_percent == 0;
    }
    if (g_str_equal(lifecycle, "burst")) {
        return connect_rate == 1000 && disconnect_rate == 0 &&
               reconnect_attempts > 0 && outage_percent == 0;
    }
    return disconnect_rate == 0 && reconnect_attempts > 0 &&
           (outage_percent == 10 || outage_percent == 25 || outage_percent == 100);
}

int
main(int argc, char *argv[])
{
    GOptionContext *option_context;
    GError *error = NULL;
    GPtrArray *targets = NULL;
    gchar *username = NULL;
    gchar *password = NULL;
    RunContext run = {0};
    guint target_index;
    guint reader_offset;
    guint signal_int_id;
    guint signal_term_id;
    guint started_snapshot;
    guint ready_snapshot;
    guint failed_snapshot;
    gboolean lifecycle_complete = TRUE;
    gint exit_code;
    guint64 rtp_packets_snapshot = 0;
    struct timex clock_state = {0};
    gint clock_status;

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
        !safe_token(codec, 4) ||
        !(g_str_equal(codec, "h264") || g_str_equal(codec, "h265")) ||
        connect_rate < 0 || connect_rate > 1000 || hold_seconds < 1 ||
        hold_seconds > 172800 || events_file == NULL ||
        !g_path_is_absolute(events_file) || !safe_token(generator_host, 253) ||
        !safe_sha256(profile_sha256) || !safe_sha256(reader_plan_sha256) ||
        start_unix_ms < 0 || !valid_lifecycle_configuration()) {
        g_printerr("configuration_error: invalid_reader_configuration\n");
        return 2;
    }
    targets = read_plan(&error);
    if (targets == NULL || !read_credentials(&username, &password, &error)) {
        g_printerr("configuration_error: %s\n",
                   error == NULL ? "invalid_reader_plan" : error->message);
        g_clear_error(&error);
        g_clear_pointer(&targets, g_ptr_array_unref);
        wipe_and_free(username);
        wipe_and_free(password);
        return 2;
    }

    run.events = g_fopen(events_file, "wx");
    if (run.events == NULL) {
        g_printerr("events_error: unable_to_create_exclusive_output\n");
        g_ptr_array_unref(targets);
        wipe_and_free(username);
        wipe_and_free(password);
        return 2;
    }
    g_chmod(events_file, 0640);
    run.loop = g_main_loop_new(NULL, FALSE);
    run.readers = g_ptr_array_new_with_free_func(free_reader);
    run.connect_rate = (guint) connect_rate;
    run.hold_seconds = (guint) hold_seconds;
    run.disconnect_rate = (guint) disconnect_rate;
    run.reconnect_attempts = (guint) reconnect_attempts;
    run.backoff_base_ms = (guint) backoff_base_ms;
    run.backoff_max_ms = (guint) backoff_max_ms;
    run.outage_percent = (guint) outage_percent;
    run.seed = (guint) scenario_seed;
    run.schedule_shards = (guint) schedule_shards;
    run.schedule_shard_index = (guint) schedule_shard_index;
    run.global_reader_count = (guint) global_reader_count;
    run.allow_failures = allow_failures;
    run.lifecycle = lifecycle;
    g_mutex_init(&run.lock);
    clock_status = adjtimex(&clock_state);
    run.clock_synchronized =
        clock_status != TIME_ERROR && (clock_state.status & STA_UNSYNC) == 0;
    run.clock_max_error_ms =
        MAX(clock_state.maxerror, clock_state.esterror) / 1000.0;
    run.process_start_unix_ms = unix_time_ms();
    run.scheduled_start_unix_ms =
        start_unix_ms == 0 ? run.process_start_unix_ms : start_unix_ms;
    if (run.process_start_unix_ms > run.scheduled_start_unix_ms) {
        g_printerr("configuration_error: coordinated_start_is_not_in_future\n");
        g_ptr_array_unref(targets);
        g_ptr_array_unref(run.readers);
        g_main_loop_unref(run.loop);
        g_mutex_clear(&run.lock);
        fclose(run.events);
        wipe_and_free(username);
        wipe_and_free(password);
        return 2;
    }

    for (target_index = 0; target_index < targets->len; target_index++) {
        PlanTarget *target = g_ptr_array_index(targets, target_index);
        for (reader_offset = 0; reader_offset < target->reader_count; reader_offset++) {
            Reader *reader = create_reader(
                &run, target->reader_id_start + reader_offset, target->path,
                username, password, &error);
            if (reader == NULL) {
                g_printerr("pipeline_error: %s\n", error->message);
                g_clear_error(&error);
                g_ptr_array_unref(targets);
                g_ptr_array_unref(run.readers);
                g_main_loop_unref(run.loop);
                g_mutex_clear(&run.lock);
                fclose(run.events);
                wipe_and_free(username);
                wipe_and_free(password);
                return 3;
            }
            g_ptr_array_add(run.readers, reader);
            if (reader->id >= run.global_reader_count) {
                g_printerr("configuration_error: reader_id_exceeds_global_count\n");
                g_ptr_array_unref(targets);
                g_ptr_array_unref(run.readers);
                g_main_loop_unref(run.loop);
                g_mutex_clear(&run.lock);
                fclose(run.events);
                wipe_and_free(username);
                wipe_and_free(password);
                return 2;
            }
        }
    }
    g_ptr_array_unref(targets);
    wipe_and_free(username);
    wipe_and_free(password);

    run.epoch_us = g_get_monotonic_time() +
                   (run.scheduled_start_unix_ms - unix_time_ms()) * 1000;
    signal_int_id = g_unix_signal_add(SIGINT, interrupt_run, &run);
    signal_term_id = g_unix_signal_add(SIGTERM, interrupt_run, &run);
    schedule_next_reader(&run);
    g_main_loop_run(run.loop);
    g_atomic_int_set(&run.stopping, TRUE);
    g_source_remove(signal_int_id);
    g_source_remove(signal_term_id);
    if (run.start_source_id != 0) {
        g_source_remove(run.start_source_id);
        run.start_source_id = 0;
    }
    if (run.stop_source_id != 0) {
        g_source_remove(run.stop_source_id);
        run.stop_source_id = 0;
    }
    if (run.lifecycle_source_id != 0) {
        g_source_remove(run.lifecycle_source_id);
        run.lifecycle_source_id = 0;
    }
    for (target_index = 0; target_index < run.readers->len; target_index++) {
        Reader *reader = g_ptr_array_index(run.readers, target_index);
        if (!g_atomic_int_get(&reader->connected) ||
            reader->reconnect_source_id != 0) {
            lifecycle_complete = FALSE;
        }
        gst_element_set_state(reader->pipeline, GST_STATE_NULL);
        gst_element_get_state(reader->pipeline, NULL, NULL, 5 * GST_SECOND);
        rtp_packets_snapshot += reader->rtp_packets;
        if (g_atomic_int_get(&reader->outage_member) &&
            !g_atomic_int_get(&reader->outage_recovered)) {
            lifecycle_complete = FALSE;
        }
    }
    if (g_str_equal(run.lifecycle, "outage") && !run.outage_injected) {
        lifecycle_complete = FALSE;
    }
    if (g_str_equal(run.lifecycle, "steady") && run.injected_disconnects == 0) {
        lifecycle_complete = FALSE;
    }
    while (g_main_context_pending(NULL)) {
        g_main_context_iteration(NULL, FALSE);
    }
    g_mutex_lock(&run.lock);
    started_snapshot = run.started_readers;
    ready_snapshot = run.ready_readers;
    failed_snapshot = run.failed_attempts;
    g_mutex_unlock(&run.lock);
    if (!run.normal_completion || run.interrupted ||
        started_snapshot != run.readers->len || ready_snapshot != run.readers->len ||
        !lifecycle_complete) {
        exit_code = 6;
    } else if (!run.allow_failures && failed_snapshot != 0) {
        exit_code = 5;
    } else {
        exit_code = 0;
    }
    g_mutex_lock(&run.lock);
    g_fprintf(run.events,
              "{\"event\":\"run_completed\",\"at_monotonic_ms\":%.3f,"
              "\"started_readers\":%u,\"ready_readers\":%u,"
              "\"failed_attempts\":%u,\"normal_completion\":%s,"
              "\"interrupted\":%s,\"lifecycle_complete\":%s,"
              "\"exit_code\":%d,\"schedule_shard_index\":%u,"
              "\"schedule_shards\":%u,\"generator_host\":\"%s\","
              "\"profile_sha256\":\"%s\","
              "\"reader_plan_sha256\":\"%s\","
              "\"scheduled_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"process_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"process_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"clock_synchronized\":%s,\"clock_max_error_ms\":%.3f,"
              "\"rtp_packets\":%" G_GUINT64_FORMAT "}\n",
              event_time_ms(&run), started_snapshot, ready_snapshot,
              failed_snapshot, run.normal_completion ? "true" : "false",
              run.interrupted ? "true" : "false",
              lifecycle_complete ? "true" : "false", exit_code,
              run.schedule_shard_index, run.schedule_shards, generator_host,
              profile_sha256, reader_plan_sha256,
              run.scheduled_start_unix_ms, run.process_start_unix_ms,
              unix_time_ms(), run.clock_synchronized ? "true" : "false",
              run.clock_max_error_ms, rtp_packets_snapshot);
    fflush(run.events);
    fsync(fileno(run.events));
    g_mutex_unlock(&run.lock);
    g_print("SUMMARY started=%u decodable=%u failed=%u transport=tcp "
            "completed=%s interrupted=%s\n",
            started_snapshot, ready_snapshot, failed_snapshot,
            run.normal_completion ? "true" : "false",
            run.interrupted ? "true" : "false");
    g_ptr_array_unref(run.readers);
    g_main_loop_unref(run.loop);
    g_mutex_clear(&run.lock);
    fclose(run.events);
    g_free(server_host);
    g_free(reader_plan_file);
    g_free(codec);
    g_free(credentials_file);
    g_free(events_file);
    g_free(lifecycle);
    g_free(generator_host);
    g_free(profile_sha256);
    g_free(reader_plan_sha256);
    return exit_code;
}
