#define _GNU_SOURCE

#include <gst/gst.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtsp/gstrtspmessage.h>
#include <glib-unix.h>
#include <glib/gstdio.h>

#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
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
    gboolean valid;
    guint cycle;
    guint phase;
    guint64 received_packets;
    guint64 sequence_expected_packets;
    guint64 sequence_gaps;
    gint64 first_at_us;
    gint64 last_at_us;
    guint16 last_sequence;
    gboolean sequence_valid;
    atomic_uint_fast64_t parse_failures;
} RtpTrackEvidence;

typedef struct {
    guint id;
    gchar *path;
    GstElement *pipeline;
    guint bus_watch_id;
    guint reconnect_source_id;
    guint cycle;
    guint generation;
    guint measured_schedule_index;
    gboolean warm_anchor;
    guint failure_retries;
    gint64 describe_at_us;
    gint64 play_at_us;
    volatile gint decodable_seen;
    gboolean ever_decodable;
    gboolean failed_cycle;
    volatile gint connected;
    volatile gint outage_member;
    volatile gint outage_recovered;
    atomic_uint_fast64_t rtp_packets;
    atomic_uint_fast64_t measurement_rtp_packets;
    atomic_uint_fast64_t soak_rtp_packets;
    atomic_uint_fast64_t measurement_rtp_sequence_gaps;
    atomic_uint_fast64_t soak_rtp_sequence_gaps;
    RtpTrackEvidence video_track;
    atomic_uint_fast64_t audio_rtp_packets;
    atomic_uint_fast64_t measurement_audio_rtp_packets;
    atomic_uint_fast64_t soak_audio_rtp_packets;
    atomic_uint_fast64_t measurement_audio_rtp_sequence_gaps;
    atomic_uint_fast64_t soak_audio_rtp_sequence_gaps;
    RtpTrackEvidence audio_track;
    GstElement *audio_sink;
    RunContext *run;
} Reader;

typedef struct {
    gchar *path;
    guint reader_count;
    guint reader_id_start;
    guint warm_anchor_count;
    guint measured_schedule_start;
} PlanTarget;

struct _RunContext {
    GMainLoop *loop;
    GThread *main_thread;
    GPtrArray *readers;
    FILE *events;
    GMutex lock;
    gint64 epoch_us;
    gint64 anchor_epoch_us;
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
    guint anchor_source_id;
    guint stop_source_id;
    guint lifecycle_source_id;
    guint clock_source_id;
    guint steady_cursor;
    guint next_lifecycle_slot;
    guint lifecycle_scheduled_slots;
    guint injected_disconnects;
    atomic_uint_fast64_t measurement_rtp_packets;
    atomic_uint_fast64_t soak_rtp_packets;
    atomic_uint_fast64_t measurement_rtp_sequence_gaps;
    atomic_uint_fast64_t soak_rtp_sequence_gaps;
    gint64 next_disconnect_us;
    gint64 stop_deadline_us;
    gint64 lifecycle_epoch_us;
    gint64 measurement_end_epoch_us;
    gint64 workload_end_epoch_us;
    gboolean allow_failures;
    gboolean normal_completion;
    gboolean interrupted;
    gboolean outage_injected;
    gboolean lifecycle_started;
    volatile gint stopping;
    gint64 scheduled_start_unix_ms;
    gint64 anchor_start_unix_ms;
    gint64 ramp_end_unix_ms;
    gint64 lifecycle_start_unix_ms;
    gint64 measurement_start_unix_ms;
    gint64 measurement_end_unix_ms;
    gint64 scheduled_workload_end_unix_ms;
    gint64 process_start_unix_ms;
    gint64 workload_end_unix_ms;
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
static gint64 anchor_start_unix_ms = 0;
static gint64 ramp_end_unix_ms = 0;
static gint64 lifecycle_start_unix_ms = 0;
static gint64 measurement_start_unix_ms = 0;
static gint64 measurement_end_unix_ms = 0;
static gint64 workload_end_unix_ms = 0;
static gint evidence_grace_seconds = 0;
static gboolean allow_failures = FALSE;
static gboolean expect_audio = FALSE;

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
    {"anchor-start-unix-ms", 0, 0, G_OPTION_ARG_INT64, &anchor_start_unix_ms,
     "Future warm-anchor start epoch in milliseconds", "MILLISECONDS"},
    {"ramp-end-unix-ms", 0, 0, G_OPTION_ARG_INT64, &ramp_end_unix_ms,
     "Common measured-reader ramp end in milliseconds", "MILLISECONDS"},
    {"lifecycle-start-unix-ms", 0, 0, G_OPTION_ARG_INT64,
     &lifecycle_start_unix_ms,
     "Common future lifecycle epoch in milliseconds", "MILLISECONDS"},
    {"measurement-start-unix-ms", 0, 0, G_OPTION_ARG_INT64,
     &measurement_start_unix_ms,
     "Common measured-window start in milliseconds", "MILLISECONDS"},
    {"measurement-end-unix-ms", 0, 0, G_OPTION_ARG_INT64,
     &measurement_end_unix_ms,
     "Common measured-window end in milliseconds", "MILLISECONDS"},
    {"workload-end-unix-ms", 0, 0, G_OPTION_ARG_INT64,
     &workload_end_unix_ms,
     "Common absolute workload end in milliseconds", "MILLISECONDS"},
    {"evidence-grace-seconds", 0, 0, G_OPTION_ARG_INT,
     &evidence_grace_seconds,
     "Post-workload PID observation barrier", "SECONDS"},
    {"allow-failures", 0, 0, G_OPTION_ARG_NONE, &allow_failures,
     "Allow recorded failures only after a complete non-interrupted run", NULL},
    {"audio", 0, 0, G_OPTION_ARG_NONE, &expect_audio,
     "Require and measure the controlled Opus RTP track", NULL},
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

static void
update_clock_proof(RunContext *run)
{
    struct timex state = {0};
    gint status = adjtimex(&state);
    gboolean synchronized =
        status >= 0 && status != TIME_ERROR && (state.status & STA_UNSYNC) == 0;
    gdouble current_error_ms =
        status < 0 ? 1000000000000.0 : MAX(state.maxerror, state.esterror) / 1000.0;

    run->clock_synchronized = run->clock_synchronized && synchronized;
    run->clock_max_error_ms = MAX(run->clock_max_error_ms, current_error_ms);
}

static gboolean
check_clock_proof(gpointer user_data)
{
    RunContext *run = user_data;
    update_clock_proof(run);
    return G_SOURCE_CONTINUE;
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
static void finalize_reader_rtp_segments(Reader *reader);

static gboolean
quiesce_reader_pipeline(Reader *reader)
{
    GstState current = GST_STATE_VOID_PENDING;
    GstState pending = GST_STATE_VOID_PENDING;
    GstStateChangeReturn result;

    result = gst_element_set_state(reader->pipeline, GST_STATE_NULL);
    if (result == GST_STATE_CHANGE_FAILURE) {
        return FALSE;
    }
    result = gst_element_get_state(reader->pipeline, &current, &pending,
                                   5 * GST_SECOND);
    return result == GST_STATE_CHANGE_SUCCESS && current == GST_STATE_NULL &&
           pending == GST_STATE_VOID_PENDING;
}

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
        if (quiesce_reader_pipeline(reader)) {
            finalize_reader_rtp_segments(reader);
            schedule_reconnect(reader, FALSE);
        }
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
    gint64 now;
    gint64 target_us;
    guint delay_ms;

    if (run->lifecycle_started || run->ready_readers != run->readers->len) {
        return;
    }
    run->lifecycle_started = TRUE;
    now = g_get_monotonic_time();
    target_us = run->lifecycle_epoch_us;
    if (g_str_equal(run->lifecycle, "outage")) {
        delay_ms = MAX(
            1U, (guint) ((MAX(0, target_us - now) + 999) / 1000U));
        run->lifecycle_source_id = g_timeout_add(delay_ms, inject_outage, run);
    } else if (g_str_equal(run->lifecycle, "steady")) {
        guint64 offset_us =
            ((guint64) run->schedule_shard_index * G_USEC_PER_SEC) /
            run->disconnect_rate;
        run->next_disconnect_us = target_us + (gint64) offset_us;
        delay_ms = MAX(
            1U,
            (guint) ((MAX(0, run->next_disconnect_us - now) + 999) / 1000U));
        run->lifecycle_source_id =
            g_timeout_add(delay_ms, steady_disconnect, run);
    }
}

typedef struct {
    Reader *reader;
    guint cycle;
    guint generation;
    gint64 observed_at_us;
    gint64 describe_at_us;
    gint64 play_at_us;
} DecodableNotice;

static gboolean
process_decodable(gpointer user_data)
{
    DecodableNotice *notice = user_data;
    Reader *reader = notice->reader;
    RunContext *run = reader->run;
    gint64 now = notice->observed_at_us;

    g_assert(g_thread_self() == run->main_thread);
    if (g_atomic_int_get(&run->stopping)) {
        g_free(notice);
        return G_SOURCE_REMOVE;
    }
    g_mutex_lock(&run->lock);
    if (notice->generation != reader->generation ||
        notice->cycle != reader->cycle) {
        g_mutex_unlock(&run->lock);
        g_free(notice);
        return G_SOURCE_REMOVE;
    }
    if (notice->describe_at_us == 0 || notice->play_at_us == 0) {
        g_mutex_unlock(&run->lock);
        record_failure(reader, "state_change_failure");
        g_free(notice);
        return G_SOURCE_REMOVE;
    }
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
              "\"play_to_first_decodable_ms\":%.3f,"
              "\"access_unit\":true}\n",
              reader->id, notice->cycle, reader->path, event_time_ms(run),
              (now - notice->describe_at_us) / 1000.0,
              (now - notice->play_at_us) / 1000.0);
    fflush(run->events);
    g_atomic_int_set(&reader->connected, TRUE);
    start_lifecycle_if_ready(run);
    g_mutex_unlock(&run->lock);
    g_free(notice);
    return G_SOURCE_REMOVE;
}

static gboolean
buffer_contains_random_access_unit(GstBuffer *buffer)
{
    GstMapInfo map = GST_MAP_INFO_INIT;
    gsize offset = 0;
    gboolean found = FALSE;

    /* HEADER can coexist with IDR/IRAP when an AU carries codec parameters. */
    if (!gst_buffer_map(buffer, &map, GST_MAP_READ)) {
        return FALSE;
    }
    while (offset + 3 < map.size) {
        gsize nal_offset;
        guint nal_type;

        if (map.data[offset] != 0 || map.data[offset + 1] != 0) {
            offset++;
            continue;
        }
        if (map.data[offset + 2] == 1) {
            nal_offset = offset + 3;
        } else if (offset + 4 < map.size && map.data[offset + 2] == 0 &&
                   map.data[offset + 3] == 1) {
            nal_offset = offset + 4;
        } else {
            offset++;
            continue;
        }
        if (nal_offset >= map.size) {
            break;
        }
        if (g_str_equal(codec, "h264")) {
            nal_type = map.data[nal_offset] & 0x1fU;
            found = nal_type == 5U;
        } else {
            nal_type = (map.data[nal_offset] >> 1U) & 0x3fU;
            found = nal_type >= 16U && nal_type <= 21U;
        }
        if (found) {
            break;
        }
        offset = nal_offset + 1;
    }
    gst_buffer_unmap(buffer, &map);
    return found;
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
    if (g_atomic_int_get(&reader->decodable_seen)) {
        return;
    }
    if (GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT) ||
        GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DECODE_ONLY) ||
        GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_CORRUPTED) ||
        GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_GAP) ||
        !buffer_contains_random_access_unit(buffer) ||
        !g_atomic_int_compare_and_exchange(&reader->decodable_seen, FALSE, TRUE)) {
        return;
    }
    notice = g_new0(DecodableNotice, 1);
    notice->reader = reader;
    notice->observed_at_us = g_get_monotonic_time();
    g_mutex_lock(&run->lock);
    notice->cycle = reader->cycle;
    notice->generation = reader->generation;
    notice->describe_at_us = reader->describe_at_us;
    notice->play_at_us = reader->play_at_us;
    g_mutex_unlock(&run->lock);
    g_idle_add_full(G_PRIORITY_DEFAULT, process_decodable, notice, NULL);
}

typedef struct {
    Reader *reader;
    gboolean audio;
} RtpProbeContext;

static void
emit_rtp_segment(Reader *reader, RtpTrackEvidence *track,
                 gboolean audio)
{
    RunContext *run = reader->run;
    const gchar *phase;

    if (!track->valid) {
        return;
    }
    phase = track->phase == 1 ? "measurement" : "soak";
    g_mutex_lock(&run->lock);
    g_fprintf(
        run->events,
        "{\"event\":\"reader_rtp_segment\",\"reader_id\":%u,"
        "\"cycle\":%u,\"path\":\"%s\",\"track\":\"%s\","
        "\"phase\":\"%s\",\"first_at_monotonic_ms\":%.3f,"
        "\"last_at_monotonic_ms\":%.3f,\"received_packets\":%" G_GUINT64_FORMAT ","
        "\"sequence_expected_packets\":%" G_GUINT64_FORMAT ","
        "\"sequence_gaps\":%" G_GUINT64_FORMAT "}\n",
        reader->id, track->cycle, reader->path, audio ? "audio" : "video",
        phase, (track->first_at_us - run->epoch_us) / 1000.0,
        (track->last_at_us - run->epoch_us) / 1000.0,
        track->received_packets, track->sequence_expected_packets,
        track->sequence_gaps);
    fflush(run->events);
    g_mutex_unlock(&run->lock);
    track->valid = FALSE;
}

static void
finalize_reader_rtp_segments(Reader *reader)
{
    emit_rtp_segment(reader, &reader->video_track, FALSE);
    emit_rtp_segment(reader, &reader->audio_track, TRUE);
}

static GstPadProbeReturn
count_rtp_packet(GstPad *pad G_GNUC_UNUSED, GstPadProbeInfo *info,
                 gpointer user_data)
{
    RtpProbeContext *probe = user_data;
    Reader *reader = probe->reader;
    if ((GST_PAD_PROBE_INFO_TYPE(info) & GST_PAD_PROBE_TYPE_BUFFER) != 0) {
        GstRTPBuffer rtp = GST_RTP_BUFFER_INIT;
        GstBuffer *buffer = GST_PAD_PROBE_INFO_BUFFER(info);
        gint64 now;
        guint phase = 0;
        gboolean connected;
        guint16 sequence;
        guint16 delta = 1;
        RtpTrackEvidence *track =
            probe->audio ? &reader->audio_track : &reader->video_track;
        atomic_uint_fast64_t *total_packets = probe->audio
                                                  ? &reader->audio_rtp_packets
                                                  : &reader->rtp_packets;
        atomic_uint_fast64_t *measurement_packets =
            probe->audio ? &reader->measurement_audio_rtp_packets
                         : &reader->measurement_rtp_packets;
        atomic_uint_fast64_t *soak_packets =
            probe->audio ? &reader->soak_audio_rtp_packets
                         : &reader->soak_rtp_packets;
        atomic_uint_fast64_t *measurement_gaps =
            probe->audio ? &reader->measurement_audio_rtp_sequence_gaps
                         : &reader->measurement_rtp_sequence_gaps;
        atomic_uint_fast64_t *soak_gaps =
            probe->audio ? &reader->soak_audio_rtp_sequence_gaps
                         : &reader->soak_rtp_sequence_gaps;
        if (!gst_rtp_buffer_map(buffer, GST_MAP_READ, &rtp)) {
            atomic_fetch_add_explicit(&track->parse_failures, 1,
                                      memory_order_relaxed);
            return GST_PAD_PROBE_OK;
        }
        sequence = gst_rtp_buffer_get_seq(&rtp);
        connected = g_atomic_int_get(&reader->connected);
        now = g_get_monotonic_time();
        connected = connected && g_atomic_int_get(&reader->connected);
        if (now >= reader->run->lifecycle_epoch_us &&
            now < reader->run->measurement_end_epoch_us) {
            phase = 1;
        } else if (now >= reader->run->measurement_end_epoch_us &&
                   now < reader->run->workload_end_epoch_us) {
            phase = 2;
        }
        atomic_fetch_add_explicit(total_packets, 1, memory_order_relaxed);
        if (phase == 1 && connected) {
            atomic_fetch_add_explicit(measurement_packets, 1,
                                      memory_order_relaxed);
            if (!probe->audio) {
                atomic_fetch_add_explicit(
                    &reader->run->measurement_rtp_packets, 1,
                    memory_order_relaxed);
            }
        } else if (phase == 2 && connected) {
            atomic_fetch_add_explicit(soak_packets, 1, memory_order_relaxed);
            if (!probe->audio) {
                atomic_fetch_add_explicit(&reader->run->soak_rtp_packets, 1,
                                          memory_order_relaxed);
            }
        }
        if (phase != 0 && connected) {
            if (!track->valid || track->phase != phase ||
                track->cycle != reader->cycle) {
                emit_rtp_segment(reader, track, probe->audio);
                track->valid = TRUE;
                track->cycle = reader->cycle;
                track->phase = phase;
                track->received_packets = 1;
                track->sequence_expected_packets = 1;
                track->sequence_gaps = 0;
                track->first_at_us = now;
                track->last_at_us = now;
                if (track->sequence_valid) {
                    delta = (guint16) (sequence - track->last_sequence);
                    track->sequence_expected_packets = delta;
                    if (delta > 1) {
                        track->sequence_gaps = (guint64) delta - 1;
                    }
                }
            } else {
                delta = (guint16) (sequence - track->last_sequence);
                track->received_packets++;
                track->sequence_expected_packets += delta;
                track->last_at_us = now;
                if (delta > 1) {
                    track->sequence_gaps += (guint64) delta - 1;
                }
            }
            if (delta > 1) {
                atomic_fetch_add_explicit(
                    phase == 1 ? measurement_gaps : soak_gaps,
                    (guint64) delta - 1, memory_order_relaxed);
                if (!probe->audio) {
                    atomic_fetch_add_explicit(
                        phase == 1
                            ? &reader->run->measurement_rtp_sequence_gaps
                            : &reader->run->soak_rtp_sequence_gaps,
                        (guint64) delta - 1, memory_order_relaxed);
                }
            }
        }
        track->sequence_valid = TRUE;
        track->last_sequence = sequence;
        gst_rtp_buffer_unmap(&rtp);
    }
    return GST_PAD_PROBE_OK;
}

static void
on_source_pad_added(GstElement *source G_GNUC_UNUSED, GstPad *pad,
                    gpointer user_data)
{
    GstCaps *caps = gst_pad_get_current_caps(pad);
    const GstStructure *structure;
    const gchar *media;
    RtpProbeContext *probe;

    if (caps == NULL) {
        caps = gst_pad_query_caps(pad, NULL);
    }
    if (caps == NULL || gst_caps_is_empty(caps)) {
        if (caps != NULL) {
            gst_caps_unref(caps);
        }
        return;
    }
    structure = gst_caps_get_structure(caps, 0);
    media = gst_structure_get_string(structure, "media");
    if (g_strcmp0(media, "video") == 0 ||
        (expect_audio && g_strcmp0(media, "audio") == 0)) {
        gboolean is_audio = g_strcmp0(media, "audio") == 0;
        probe = g_new0(RtpProbeContext, 1);
        probe->reader = user_data;
        probe->audio = is_audio;
        gst_pad_add_probe(pad, GST_PAD_PROBE_TYPE_BUFFER, count_rtp_packet,
                          probe, g_free);
        if (is_audio) {
            GstPad *sink_pad = gst_element_get_static_pad(
                ((Reader *) user_data)->audio_sink, "sink");
            if (sink_pad == NULL || gst_pad_link(pad, sink_pad) != GST_PAD_LINK_OK) {
                atomic_fetch_add_explicit(
                    &((Reader *) user_data)->audio_track.parse_failures, 1,
                    memory_order_relaxed);
            }
            g_clear_object(&sink_pad);
        }
    }
    gst_caps_unref(caps);
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
              gboolean warm_anchor, guint measured_schedule_index,
              const gchar *username, const gchar *password, GError **error)
{
    Reader *reader;
    gchar *url_host;
    gchar *url;
    gchar *escaped_url;
    gchar *launch;
    const gchar *depay;
    const gchar *parser;
    const gchar *parsed_caps;
    GstElement *source;
    GstElement *sink;
    GstBus *bus;

    depay = g_str_equal(codec, "h264") ? "rtph264depay" : "rtph265depay";
    parser = g_str_equal(codec, "h264") ? "h264parse" : "h265parse";
    parsed_caps = g_str_equal(codec, "h264")
                      ? "video/x-h264,stream-format=byte-stream,alignment=au"
                      : "video/x-h265,stream-format=byte-stream,alignment=au";
    url_host = strchr(server_host, ':') == NULL
                   ? g_strdup(server_host)
                   : g_strdup_printf("[%s]", server_host);
    url = g_strdup_printf("rtsp://%s:%d/%s", url_host, server_port, path);
    escaped_url = g_strescape(url, NULL);
    launch = g_strdup_printf(
        "rtspsrc name=source location=\"%s\" protocols=tcp latency=0 "
        "do-rtsp-keep-alive=true ! %s ! %s ! %s ! "
        "fakesink name=sink sync=false async=false signal-handoffs=true",
        escaped_url, depay, parser, parsed_caps);

    reader = g_new0(Reader, 1);
    atomic_init(&reader->rtp_packets, 0);
    atomic_init(&reader->measurement_rtp_packets, 0);
    atomic_init(&reader->soak_rtp_packets, 0);
    atomic_init(&reader->measurement_rtp_sequence_gaps, 0);
    atomic_init(&reader->soak_rtp_sequence_gaps, 0);
    atomic_init(&reader->video_track.parse_failures, 0);
    atomic_init(&reader->audio_rtp_packets, 0);
    atomic_init(&reader->measurement_audio_rtp_packets, 0);
    atomic_init(&reader->soak_audio_rtp_packets, 0);
    atomic_init(&reader->measurement_audio_rtp_sequence_gaps, 0);
    atomic_init(&reader->soak_audio_rtp_sequence_gaps, 0);
    atomic_init(&reader->audio_track.parse_failures, 0);
    reader->id = reader_id;
    reader->warm_anchor = warm_anchor;
    reader->measured_schedule_index = measured_schedule_index;
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
    if (expect_audio) {
        reader->audio_sink = gst_element_factory_make("fakesink", NULL);
        if (reader->audio_sink == NULL) {
            g_set_error_literal(error, G_OPTION_ERROR,
                                G_OPTION_ERROR_FAILED,
                                "audio_sink_element_missing");
            gst_object_unref(reader->pipeline);
            g_free(reader->path);
            g_free(reader);
            return NULL;
        }
        g_object_set(reader->audio_sink, "sync", FALSE, "async", FALSE,
                     NULL);
        if (!gst_bin_add(GST_BIN(reader->pipeline), reader->audio_sink)) {
            g_set_error_literal(error, G_OPTION_ERROR,
                                G_OPTION_ERROR_FAILED,
                                "audio_sink_add_failed");
            gst_object_unref(reader->audio_sink);
            gst_object_unref(reader->pipeline);
            g_free(reader->path);
            g_free(reader);
            return NULL;
        }
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
start_reader(Reader *reader, gboolean reconnect)
{
    RunContext *run = reader->run;
    GstStateChangeReturn state_change;

    g_mutex_lock(&run->lock);
    if (reconnect) {
        reader->cycle++;
    }
    reader->generation++;
    reader->video_track.sequence_valid = FALSE;
    reader->audio_track.sequence_valid = FALSE;
    reader->describe_at_us = 0;
    reader->play_at_us = 0;
    reader->failed_cycle = FALSE;
    g_atomic_int_set(&reader->connected, FALSE);
    g_atomic_int_set(&reader->decodable_seen, FALSE);
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
    start_reader(reader, TRUE);
    return G_SOURCE_REMOVE;
}

static gboolean schedule_next_reader(gpointer user_data);

static gboolean
start_warm_anchors(gpointer user_data)
{
    RunContext *run = user_data;
    guint index;

    run->anchor_source_id = 0;
    for (index = 0; index < run->readers->len; index++) {
        Reader *reader = g_ptr_array_index(run->readers, index);
        if (reader->warm_anchor) {
            start_reader(reader, FALSE);
            run->started_readers++;
        }
    }
    return G_SOURCE_REMOVE;
}

static gboolean
start_next_reader(gpointer user_data)
{
    RunContext *run = user_data;
    Reader *reader;

    run->start_source_id = 0;
    while (run->next_reader < run->readers->len &&
           ((Reader *) g_ptr_array_index(run->readers, run->next_reader))->warm_anchor) {
        run->next_reader++;
    }
    if (run->next_reader >= run->readers->len) {
        return G_SOURCE_REMOVE;
    }
    reader = g_ptr_array_index(run->readers, run->next_reader++);
    start_reader(reader, FALSE);
    run->started_readers++;
    if (run->next_reader >= run->readers->len) {
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

    run->start_source_id = 0;
    now = g_get_monotonic_time();
    while (run->next_reader < run->readers->len &&
           ((Reader *) g_ptr_array_index(run->readers, run->next_reader))->warm_anchor) {
        run->next_reader++;
    }
    if (run->next_reader >= run->readers->len) {
        return G_SOURCE_REMOVE;
    }
    if (run->connect_rate == 0) {
        if (now < run->epoch_us) {
            delay_us = run->epoch_us - now;
            run->start_source_id = g_timeout_add(
                MAX(1U, (guint) ((delay_us + 999) / 1000)),
                schedule_next_reader, run);
            return G_SOURCE_REMOVE;
        }
        while (run->next_reader < run->readers->len) {
            Reader *reader = g_ptr_array_index(run->readers, run->next_reader++);
            if (!reader->warm_anchor) {
                start_reader(reader, FALSE);
                run->started_readers++;
            }
        }
        return G_SOURCE_REMOVE;
    }
    interval_us = G_USEC_PER_SEC / run->connect_rate;
    next_reader = g_ptr_array_index(run->readers, run->next_reader);
    delay_us = MAX(
        0,
        run->epoch_us +
            ((gint64) next_reader->measured_schedule_index * interval_us) - now);
    run->start_source_id =
        g_timeout_add(MAX(1U, (guint) ((delay_us + 999) / 1000)),
                      start_next_reader, run);
    return G_SOURCE_REMOVE;
}

static void
disconnect_for_lifecycle(Reader *reader, gboolean full_window,
                         guint lifecycle_slot)
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
              "\"at_monotonic_ms\":%.3f,"
              "\"at_unix_ms\":%" G_GINT64_FORMAT ","
              "\"injected\":true,\"lifecycle_slot\":%u}\n",
              reader->id, reader->cycle, reader->path, event_time_ms(run),
              unix_time_ms(), lifecycle_slot);
    fflush(run->events);
    g_mutex_unlock(&run->lock);
    if (!quiesce_reader_pipeline(reader)) {
        record_failure(reader, "state_change_failure");
        return;
    }
    finalize_reader_rtp_segments(reader);
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
    if (now + ((gint64) run->backoff_base_ms * 1000) >= run->stop_deadline_us) {
        return G_SOURCE_REMOVE;
    }
    run->lifecycle_scheduled_slots++;
    while (examined < run->readers->len) {
        Reader *reader =
            g_ptr_array_index(run->readers, run->steady_cursor % run->readers->len);
        run->steady_cursor++;
        examined++;
        if (g_atomic_int_get(&reader->connected) && reader->reconnect_source_id == 0) {
            disconnect_for_lifecycle(reader, FALSE, run->next_lifecycle_slot);
            break;
        }
    }
    run->next_lifecycle_slot += run->schedule_shards;
    run->next_disconnect_us += interval_us;
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
            run->lifecycle_scheduled_slots++;
            g_atomic_int_set(&reader->outage_member, TRUE);
            disconnect_for_lifecycle(reader, TRUE, distance);
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
        gchar *anchor_end = NULL;
        gchar *measured_start_end = NULL;
        gsize field_count;
        guint64 count;
        guint64 start;
        guint64 anchors;
        guint64 measured_start;
        guint offset;
        PlanTarget *target;

        if (lines[line_index][0] == '\0') {
            continue;
        }
        fields = g_strsplit(lines[line_index], "\t", 6);
        field_count = g_strv_length(fields);
        if (field_count != 5) {
            g_strfreev(fields);
            g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                                "reader_plan_contains_invalid_target");
            g_ptr_array_unref(targets);
            targets = NULL;
            break;
        }
        count = g_ascii_strtoull(fields[1], &count_end, 10);
        start = g_ascii_strtoull(fields[2], &start_end, 10);
        anchors = g_ascii_strtoull(fields[3], &anchor_end, 10);
        measured_start = g_ascii_strtoull(fields[4], &measured_start_end, 10);
        if (!safe_token(fields[0], 128) || count < 1 ||
            count > MAX_READERS || start >= MAX_READERS ||
            start + count > MAX_READERS || *count_end != '\0' ||
            *start_end != '\0' || *anchor_end != '\0' ||
            *measured_start_end != '\0' || measured_start >= MAX_READERS ||
            anchors > 1 ||
            anchors > count ||
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
        target->warm_anchor_count = (guint) anchors;
        target->measured_schedule_start = (guint) measured_start;
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
    guint anchor_readers = 0;
    guint signal_int_id;
    guint signal_term_id;
    guint started_snapshot;
    guint ready_snapshot;
    guint failed_snapshot;
    gboolean lifecycle_complete = TRUE;
    gint exit_code;
    guint64 rtp_packets_snapshot = 0;
    gint64 process_end_unix_ms;

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
        start_unix_ms < 0 || anchor_start_unix_ms < 0 || ramp_end_unix_ms < 0 ||
        lifecycle_start_unix_ms < 0 ||
        measurement_start_unix_ms < 0 || measurement_end_unix_ms < 0 ||
        workload_end_unix_ms < 0 ||
        evidence_grace_seconds < 0 || evidence_grace_seconds > 180 ||
        !valid_lifecycle_configuration()) {
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
    atomic_init(&run.measurement_rtp_packets, 0);
    atomic_init(&run.soak_rtp_packets, 0);
    atomic_init(&run.measurement_rtp_sequence_gaps, 0);
    atomic_init(&run.soak_rtp_sequence_gaps, 0);
    run.main_thread = g_thread_self();
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
    run.next_lifecycle_slot = (guint) schedule_shard_index;
    run.global_reader_count = (guint) global_reader_count;
    run.allow_failures = allow_failures;
    run.lifecycle = lifecycle;
    g_mutex_init(&run.lock);
    run.clock_synchronized = TRUE;
    update_clock_proof(&run);
    run.process_start_unix_ms = unix_time_ms();
    run.scheduled_start_unix_ms =
        start_unix_ms == 0 ? run.process_start_unix_ms : start_unix_ms;
    run.anchor_start_unix_ms = anchor_start_unix_ms == 0
                                   ? run.scheduled_start_unix_ms
                                   : anchor_start_unix_ms;
    run.ramp_end_unix_ms = ramp_end_unix_ms == 0
                               ? run.scheduled_start_unix_ms
                               : ramp_end_unix_ms;
    run.lifecycle_start_unix_ms = lifecycle_start_unix_ms == 0
                                      ? run.scheduled_start_unix_ms
                                      : lifecycle_start_unix_ms;
    run.measurement_start_unix_ms = measurement_start_unix_ms == 0
                                        ? run.lifecycle_start_unix_ms
                                        : measurement_start_unix_ms;
    if (workload_end_unix_ms == 0) {
        gint64 ramp_ms =
            connect_rate == 0
                ? 0
                : (((gint64) global_reader_count - 1) * 1000 + connect_rate - 1) /
                      connect_rate;
        run.scheduled_workload_end_unix_ms =
            run.scheduled_start_unix_ms + ramp_ms + (gint64) hold_seconds * 1000;
    } else {
        run.scheduled_workload_end_unix_ms = workload_end_unix_ms;
    }
    run.measurement_end_unix_ms = measurement_end_unix_ms == 0
                                      ? run.scheduled_workload_end_unix_ms
                                      : measurement_end_unix_ms;
    if (run.process_start_unix_ms > run.anchor_start_unix_ms ||
        run.anchor_start_unix_ms > run.scheduled_start_unix_ms ||
        run.ramp_end_unix_ms < run.scheduled_start_unix_ms ||
        run.ramp_end_unix_ms > run.measurement_start_unix_ms ||
        run.lifecycle_start_unix_ms < run.scheduled_start_unix_ms ||
        run.lifecycle_start_unix_ms != run.measurement_start_unix_ms ||
        run.measurement_start_unix_ms < run.scheduled_start_unix_ms ||
        run.measurement_end_unix_ms <= run.measurement_start_unix_ms ||
        run.measurement_end_unix_ms > run.scheduled_workload_end_unix_ms ||
        run.scheduled_workload_end_unix_ms <= run.scheduled_start_unix_ms ||
        ((g_str_equal(run.lifecycle, "steady") ||
          g_str_equal(run.lifecycle, "outage")) &&
         run.lifecycle_start_unix_ms >= run.scheduled_workload_end_unix_ms)) {
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
            gboolean is_anchor = reader_offset < target->warm_anchor_count;
            Reader *reader = create_reader(
                &run, target->reader_id_start + reader_offset, target->path,
                is_anchor,
                is_anchor ? 0
                          : target->measured_schedule_start + reader_offset -
                                target->warm_anchor_count,
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
            if (is_anchor) {
                anchor_readers++;
            }
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
    run.anchor_epoch_us = run.epoch_us -
                          (run.scheduled_start_unix_ms -
                           run.anchor_start_unix_ms) *
                              1000;
    run.lifecycle_epoch_us = run.epoch_us +
                             (run.lifecycle_start_unix_ms -
                              run.scheduled_start_unix_ms) *
                                 1000;
    run.measurement_end_epoch_us =
        run.epoch_us +
        (run.measurement_end_unix_ms - run.scheduled_start_unix_ms) * 1000;
    run.workload_end_epoch_us = run.epoch_us +
                                (run.scheduled_workload_end_unix_ms -
                                 run.scheduled_start_unix_ms) *
                                    1000;
    run.stop_deadline_us = run.workload_end_epoch_us;
    signal_int_id = g_unix_signal_add(SIGINT, interrupt_run, &run);
    signal_term_id = g_unix_signal_add(SIGTERM, interrupt_run, &run);
    run.clock_source_id = g_timeout_add_seconds(60, check_clock_proof, &run);
    run.stop_source_id = g_timeout_add(
        MAX(1U,
            (guint) ((MAX(0, run.workload_end_epoch_us -
                              g_get_monotonic_time()) +
                      999) /
                     1000)),
        stop_run_normal, &run);
    if (anchor_readers > 0) {
        run.anchor_source_id = g_timeout_add(
            MAX(1U,
                (guint) ((MAX(0, run.anchor_epoch_us -
                                  g_get_monotonic_time()) +
                          999) /
                         1000)),
            start_warm_anchors, &run);
    }
    schedule_next_reader(&run);
    g_main_loop_run(run.loop);
    update_clock_proof(&run);
    run.workload_end_unix_ms = unix_time_ms();
    g_atomic_int_set(&run.stopping, TRUE);
    g_source_remove(signal_int_id);
    g_source_remove(signal_term_id);
    if (run.start_source_id != 0) {
        g_source_remove(run.start_source_id);
        run.start_source_id = 0;
    }
    if (run.anchor_source_id != 0) {
        g_source_remove(run.anchor_source_id);
        run.anchor_source_id = 0;
    }
    if (run.stop_source_id != 0) {
        g_source_remove(run.stop_source_id);
        run.stop_source_id = 0;
    }
    if (run.lifecycle_source_id != 0) {
        g_source_remove(run.lifecycle_source_id);
        run.lifecycle_source_id = 0;
    }
    if (run.clock_source_id != 0) {
        g_source_remove(run.clock_source_id);
        run.clock_source_id = 0;
    }
    for (target_index = 0; target_index < run.readers->len; target_index++) {
        Reader *reader = g_ptr_array_index(run.readers, target_index);
        gboolean quiesced;
        if (!g_atomic_int_get(&reader->connected) ||
            reader->reconnect_source_id != 0) {
            lifecycle_complete = FALSE;
        }
        quiesced = quiesce_reader_pipeline(reader);
        if (!quiesced) {
            lifecycle_complete = FALSE;
        } else {
            finalize_reader_rtp_segments(reader);
        }
        rtp_packets_snapshot += atomic_load_explicit(
            &reader->rtp_packets, memory_order_relaxed);
        g_fprintf(
            run.events,
            "{\"event\":\"reader_rtp_phase\",\"reader_id\":%u,"
            "\"path\":\"%s\",\"at_monotonic_ms\":%.3f,"
            "\"audio_expected\":%s,\"quiesced\":%s,"
            "\"video_parse_failures\":%" G_GUINT64_FORMAT ","
            "\"audio_parse_failures\":%" G_GUINT64_FORMAT ","
            "\"measurement_video_rtp_packets\":%" G_GUINT64_FORMAT ","
            "\"measurement_video_rtp_sequence_gaps\":%" G_GUINT64_FORMAT ","
            "\"soak_video_rtp_packets\":%" G_GUINT64_FORMAT ","
            "\"soak_video_rtp_sequence_gaps\":%" G_GUINT64_FORMAT ","
            "\"measurement_audio_rtp_packets\":%" G_GUINT64_FORMAT ","
            "\"measurement_audio_rtp_sequence_gaps\":%" G_GUINT64_FORMAT ","
            "\"soak_audio_rtp_packets\":%" G_GUINT64_FORMAT ","
            "\"soak_audio_rtp_sequence_gaps\":%" G_GUINT64_FORMAT "}\n",
            reader->id, reader->path, event_time_ms(&run),
            expect_audio ? "true" : "false",
            quiesced ? "true" : "false",
            atomic_load_explicit(&reader->video_track.parse_failures,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->audio_track.parse_failures,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->measurement_rtp_packets,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->measurement_rtp_sequence_gaps,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->soak_rtp_packets,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->soak_rtp_sequence_gaps,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->measurement_audio_rtp_packets,
                                 memory_order_relaxed),
            atomic_load_explicit(
                &reader->measurement_audio_rtp_sequence_gaps,
                memory_order_relaxed),
            atomic_load_explicit(&reader->soak_audio_rtp_packets,
                                 memory_order_relaxed),
            atomic_load_explicit(&reader->soak_audio_rtp_sequence_gaps,
                                 memory_order_relaxed));
        if (g_atomic_int_get(&reader->outage_member) &&
            !g_atomic_int_get(&reader->outage_recovered)) {
            lifecycle_complete = FALSE;
        }
    }
    fflush(run.events);
    if (g_str_equal(run.lifecycle, "outage") && !run.outage_injected) {
        lifecycle_complete = FALSE;
    }
    if (g_str_equal(run.lifecycle, "steady") && run.injected_disconnects == 0) {
        lifecycle_complete = FALSE;
    }
    if (g_str_equal(run.lifecycle, "steady") &&
        run.injected_disconnects != run.lifecycle_scheduled_slots) {
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
    if (run.normal_completion && !run.interrupted && evidence_grace_seconds > 0) {
        g_usleep((gulong) evidence_grace_seconds * G_USEC_PER_SEC);
    }
    update_clock_proof(&run);
    process_end_unix_ms = unix_time_ms();
    if (!run.normal_completion || run.interrupted || !run.clock_synchronized ||
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
              "\"anchor_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"scheduled_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"ramp_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"lifecycle_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"measurement_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"measurement_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"scheduled_workload_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"process_start_unix_ms\":%" G_GINT64_FORMAT ","
              "\"workload_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"process_end_unix_ms\":%" G_GINT64_FORMAT ","
              "\"clock_synchronized\":%s,\"clock_max_error_ms\":%.3f,"
              "\"lifecycle_scheduled_slots\":%u,"
              "\"injected_disconnects\":%u,"
              "\"rtp_packets\":%" G_GUINT64_FORMAT ","
              "\"measurement_rtp_packets\":%" G_GUINT64_FORMAT ","
              "\"soak_rtp_packets\":%" G_GUINT64_FORMAT ","
              "\"measurement_rtp_sequence_gaps\":%" G_GUINT64_FORMAT ","
              "\"soak_rtp_sequence_gaps\":%" G_GUINT64_FORMAT "}\n",
              event_time_ms(&run), started_snapshot, ready_snapshot,
              failed_snapshot, run.normal_completion ? "true" : "false",
              run.interrupted ? "true" : "false",
              lifecycle_complete ? "true" : "false", exit_code,
              run.schedule_shard_index, run.schedule_shards, generator_host,
              profile_sha256, reader_plan_sha256,
              run.anchor_start_unix_ms,
              run.scheduled_start_unix_ms, run.ramp_end_unix_ms,
              run.lifecycle_start_unix_ms,
              run.measurement_start_unix_ms, run.measurement_end_unix_ms,
              run.scheduled_workload_end_unix_ms, run.process_start_unix_ms,
              run.workload_end_unix_ms,
              process_end_unix_ms, run.clock_synchronized ? "true" : "false",
              run.clock_max_error_ms, run.lifecycle_scheduled_slots,
              run.injected_disconnects, rtp_packets_snapshot,
              atomic_load_explicit(&run.measurement_rtp_packets,
                                   memory_order_relaxed),
              atomic_load_explicit(&run.soak_rtp_packets,
                                   memory_order_relaxed),
              atomic_load_explicit(&run.measurement_rtp_sequence_gaps,
                                   memory_order_relaxed),
              atomic_load_explicit(&run.soak_rtp_sequence_gaps,
                                   memory_order_relaxed));
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
