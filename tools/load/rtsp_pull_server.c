#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <glib-unix.h>

#include <signal.h>
#include <string.h>

#define MAX_SOURCES 10000

static gchar *listen_address = NULL;
static gint listen_port = 8554;
static gchar *mount_prefix = NULL;
static gint source_start = 0;
static gint source_count = 1;
static gchar *fixture_path = NULL;
static gchar *codec = NULL;
static gint fps = 25;
static gboolean audio = FALSE;

static GOptionEntry entries[] = {
    {"address", 'a', 0, G_OPTION_ARG_STRING, &listen_address,
     "Address to listen on", "ADDRESS"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &listen_port,
     "RTSP TCP port", "PORT"},
    {"mount-prefix", 'm', 0, G_OPTION_ARG_STRING, &mount_prefix,
     "Mount prefix, for example /source-", "PREFIX"},
    {"source-start", 0, 0, G_OPTION_ARG_INT, &source_start,
     "First zero-based source index", "INDEX"},
    {"source-count", 'n', 0, G_OPTION_ARG_INT, &source_count,
     "Number of independent RTSP source endpoints", "COUNT"},
    {"fixture", 'f', 0, G_OPTION_ARG_FILENAME, &fixture_path,
     "Absolute path to a prepared elementary-stream fixture", "PATH"},
    {"codec", 'c', 0, G_OPTION_ARG_STRING, &codec,
     "Fixture codec: h264 or h265", "CODEC"},
    {"fps", 0, 0, G_OPTION_ARG_INT, &fps,
     "Fixture frame rate", "FPS"},
    {"audio", 0, 0, G_OPTION_ARG_NONE, &audio,
     "Add a controlled 48 kHz mono Opus track", NULL},
    {NULL}
};

static gboolean
stop_main_loop(gpointer user_data)
{
    GMainLoop *loop = user_data;
    g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
}

static gboolean
valid_mount_prefix(const gchar *value)
{
    const gchar *cursor;

    if (value == NULL || value[0] != '/' || value[1] == '\0') {
        return FALSE;
    }
    for (cursor = value + 1; *cursor != '\0'; cursor++) {
        if (!(g_ascii_isalnum(*cursor) || *cursor == '-' || *cursor == '_')) {
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
validate_options(GError **error)
{
    if (listen_port < 1 || listen_port > 65535) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "port_out_of_range");
        return FALSE;
    }
    if (source_start < 0 || source_start > MAX_SOURCES || source_count < 1 ||
        source_count > MAX_SOURCES - source_start) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "source_range_out_of_range");
        return FALSE;
    }
    if (fps < 1 || fps > 240) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "fps_out_of_range");
        return FALSE;
    }
    if (!valid_mount_prefix(mount_prefix)) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "invalid_mount_prefix");
        return FALSE;
    }
    if (fixture_path == NULL || !g_path_is_absolute(fixture_path) ||
        strstr(fixture_path, "..") != NULL ||
        !g_file_test(fixture_path, G_FILE_TEST_IS_REGULAR)) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "fixture_must_be_an_absolute_regular_file");
        return FALSE;
    }
    if (g_strcmp0(codec, "h264") != 0 && g_strcmp0(codec, "h265") != 0) {
        g_set_error_literal(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                            "unsupported_codec");
        return FALSE;
    }
    return TRUE;
}

static gchar *
build_launch_line(void)
{
    const gchar *media_caps;
    const gchar *parser;
    const gchar *payloader;
    gchar *escaped_fixture;
    gchar *video;
    gchar *launch;

    if (g_strcmp0(codec, "h264") == 0) {
        media_caps = "video/x-h264,stream-format=(string)byte-stream";
        parser = "h264parse";
        payloader = "rtph264pay";
    } else {
        media_caps = "video/x-h265,stream-format=(string)byte-stream";
        parser = "h265parse";
        payloader = "rtph265pay";
    }

    escaped_fixture = g_strescape(fixture_path, NULL);
    video = g_strdup_printf(
        "multifilesrc location=\"%s\" loop=true start-index=0 stop-index=0 "
        "do-timestamp=true caps=\"%s,framerate=(fraction)%d/1\" ! "
        "%s ! identity sync=true ! %s name=pay0 pt=96 config-interval=1",
        escaped_fixture, media_caps, fps, parser, payloader);
    if (audio) {
        launch = g_strdup_printf(
            "( %s audiotestsrc is-live=true wave=silence ! "
            "audio/x-raw,format=S16LE,rate=48000,channels=1 ! "
            "opusenc bitrate=64000 ! rtpopuspay name=pay1 pt=97 )",
            video);
    } else {
        launch = g_strdup_printf("( %s )", video);
    }
    g_free(video);
    g_free(escaped_fixture);
    return launch;
}

int
main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;
    GMainLoop *loop;
    GstRTSPServer *server;
    GstRTSPMountPoints *mounts;
    gchar *service;
    gchar *launch;
    GstElement *parsed_launch;
    guint source_id;
    gint index;

    context = g_option_context_new("- prepared-fixture RTSP pull-source server");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_add_group(context, gst_init_get_option_group());
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("option_error: %s\n", error->message);
        g_clear_error(&error);
        g_option_context_free(context);
        return 2;
    }
    g_option_context_free(context);

    if (listen_address == NULL) {
        listen_address = g_strdup("127.0.0.1");
    }
    if (mount_prefix == NULL) {
        mount_prefix = g_strdup("/source-");
    }
    if (codec == NULL) {
        codec = g_strdup("h264");
    }

    if (!validate_options(&error)) {
        g_printerr("configuration_error: %s\n", error->message);
        g_clear_error(&error);
        return 2;
    }

    launch = build_launch_line();
    parsed_launch = gst_parse_launch(launch, &error);
    if (parsed_launch == NULL) {
        g_printerr("pipeline_error: %s\n", error->message);
        g_clear_error(&error);
        g_free(launch);
        return 3;
    }
    gst_object_unref(parsed_launch);

    loop = g_main_loop_new(NULL, FALSE);
    server = gst_rtsp_server_new();
    service = g_strdup_printf("%d", listen_port);
    gst_rtsp_server_set_address(server, listen_address);
    gst_rtsp_server_set_service(server, service);
    g_free(service);

    mounts = gst_rtsp_server_get_mount_points(server);
    for (index = source_start; index < source_start + source_count; index++) {
        GstRTSPMediaFactory *factory = gst_rtsp_media_factory_new();
        gchar *mount = g_strdup_printf("%s%05d", mount_prefix, index);

        gst_rtsp_media_factory_set_launch(factory, launch);
        gst_rtsp_media_factory_set_shared(factory, TRUE);
        gst_rtsp_media_factory_set_protocols(factory, GST_RTSP_LOWER_TRANS_TCP);
        gst_rtsp_mount_points_add_factory(mounts, mount, factory);
        g_free(mount);
    }
    g_object_unref(mounts);
    g_free(launch);

    source_id = gst_rtsp_server_attach(server, NULL);
    if (source_id == 0) {
        g_printerr("listen_error: unable to attach RTSP server\n");
        g_object_unref(server);
        g_main_loop_unref(loop);
        return 4;
    }

    g_unix_signal_add(SIGINT, stop_main_loop, loop);
    g_unix_signal_add(SIGTERM, stop_main_loop, loop);
    g_print(
        "READY address=%s port=%d source_start=%d source_count=%d "
        "codec=%s transport=tcp\n",
        listen_address, listen_port, source_start, source_count, codec);
    g_main_loop_run(loop);

    g_source_remove(source_id);
    g_object_unref(server);
    g_main_loop_unref(loop);
    g_free(listen_address);
    g_free(mount_prefix);
    g_free(fixture_path);
    g_free(codec);
    return 0;
}
