#!/bin/bash

# Released as open source by NCC Group Plc - https://www.nccgroup.com/
#
# Developed by:
#     Andrew Kisliakov (andrew.kisliakov@nccgroup.com)
#
# Project link: https://www.github.com/nccgroup/secretscrub/
#
# Released under AGPL-3.0. See LICENSE for more information.

POSITIONAL_ARGS=()
ANALYSE_WITH=
LOG_LEVEL=
while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--analyse-with|--analyze-with)
      ANALYSE_WITH="$2"
      shift # past argument
      shift # past value
      ;;
    -l|--log-level)
      LOG_LEVEL_ARG="--log-level $2"
      shift # past argument
      shift # past value
      ;;
    --placeholder)
      PLACEHOLDER_ARG="--placeholder $2"
      shift # past argument
      shift # past value
      ;;
    -x|--process-archives)
      PROCESS_ARCHIVES_ARG="--process-archives"
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

function test_write {
  if [ ! -w "$1" ]; then
    echo "The $2 directory is not writeable within the container. Please ensure that its owner is set to user ID $(id -u) or that write permissions are set for all users."
    exit 1
  fi
}

SRC_DIR=/src
if [ ! -d "$SRC_DIR" ]; then
  echo "No source code directory specified. This must be mapped as a volume (preferably read-only) into the Docker container using an argument of the form:"
  echo "  -v [path-to-source-on-host]:/src:ro"
  echo "For example:"
  echo "  -v /home/consultant/projects/secretscrub:/src:ro"
  exit 1
fi

ANALYSIS_DIR=/analysis
if [ "" = "$ANALYSE_WITH" -a ! -d "$ANALYSIS_DIR" ]; then 
    echo "No analysis volume specified. This should be mapped as a volume (preferably read-only) into the Docker container using an argument of the form:"
    echo "  -v [path-to-scans-on-host]:/analysis:ro"
    echo "For example:"
    echo "  -v /home/consultant/projects/secretscrub-analysis:/analysis:ro"
    exit 1
fi

TIMESTAMP=`date +"%Y%m%dT%H%M%S"`
WORK_DIR=`mktemp -d --tmpdir=/tmp secretscrub-$TIMESTAMP.XXXX`

OUT_DIR=/out
if [ ! -d "$OUT_DIR" ]; then 
    echo "No output volume specified. This should be mapped as a writable volume into the Docker container using an argument of the form:"
    echo "  -v [path-to-out-on-host]:/out"
    echo "For example:"
    echo "  -v /home/consultant/projects/secretscrub-redacted:/out"
    echo "Redirecting tool output to: $WORK_DIR ..."
    OUT_DIR="$WORK_DIR"
fi

test_write "$OUT_DIR" "output"

if [ "" = "$ANALYSE_WITH" ]; then
  test_write "$ANALYSIS_DIR" "analysis"
fi

rm -rf "$OUT_DIR/src-redacted" || exit 1
mkdir -p "$OUT_DIR/src-redacted" || exit 1

if [ "" = "$ANALYSE_WITH" ]; then
  python /app/secretscrub.py $PROCESS_ARCHIVES_ARG $LOG_LEVEL_ARG --input "$ANALYSIS_DIR" --srcdir /src --outdir "$OUT_DIR/src-redacted" --report "$OUT_DIR/secretscrub-report.csv" || exit 1
else
  python /app/secretscrub.py $PROCESS_ARCHIVES_ARG $LOG_LEVEL_ARG --analyse-with "$ANALYSE_WITH" --srcdir /src --outdir "$OUT_DIR/src-redacted" --report "$OUT_DIR/secretscrub-report.csv" || exit 1
fi

# Because the user within the Docker container may not be the same as the user 
# who owns the output directory, all files and directories are made readable
# (r) and all directories are made executable (X).
chmod -R g+rX,a+rX "$OUT_DIR"/*

echo "Done!"
