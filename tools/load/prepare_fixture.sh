#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: prepare_fixture.sh FFMPEG OUTPUT CODEC BITRATE_BPS FPS GOP_FRAMES SECONDS" >&2
  exit 2
fi

ffmpeg_binary=$1
output_path=$2
codec=$3
bitrate_bps=$4
fps=$5
gop_frames=$6
seconds=$7

if [[ $output_path != /* || -e $output_path ]]; then
  echo "fixture_error: output_must_be_new_absolute_path" >&2
  exit 2
fi
for numeric_value in "$bitrate_bps" "$fps" "$gop_frames" "$seconds"; do
  if [[ ! $numeric_value =~ ^[1-9][0-9]*$ ]]; then
    echo "fixture_error: numeric_arguments_must_be_positive_integers" >&2
    exit 2
  fi
done

case $codec in
  h264)
    encoder=libx264
    output_format=h264
    codec_options=(-x264-params "keyint=${gop_frames}:min-keyint=${gop_frames}:scenecut=0")
    ;;
  h265)
    encoder=libx265
    output_format=hevc
    codec_options=(-x265-params "pools=1:keyint=${gop_frames}:min-keyint=${gop_frames}:scenecut=0")
    ;;
  *)
    echo "fixture_error: codec_must_be_h264_or_h265" >&2
    exit 2
    ;;
esac

"$ffmpeg_binary" \
  -hide_banner -nostdin -loglevel error \
  -f lavfi -i "testsrc=size=1280x720:rate=${fps}" \
  -t "$seconds" -an -pix_fmt yuv420p -threads 1 \
  -c:v "$encoder" -b:v "$bitrate_bps" -g "$gop_frames" \
  "${codec_options[@]}" -f "$output_format" -n "$output_path"

sha256sum "$output_path"
