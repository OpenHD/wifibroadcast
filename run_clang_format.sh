#!/bin/bash

# OpenHD clang-format checking.
# Performed steps:
# Step1: Generate list of all .cpp / .h / .hpp files of this project
#        (excluding subdirectories)
# Step 2: Run clang-format
# Arguments: run with 'f' to fix things (otherwise, default, only check and report
# error if clang-format finds any issues


function append_all_sources_headers() {
    # We use .h, .cpp and .hpp in OpenHD
    TMP_FILE_LIST="$(find "$1" | grep -E ".*(\.cpp|\.h|\.hpp)$")"
    #TMP_FILE_LIST+='\n'
    FILE_LIST+=$'\n'
    FILE_LIST+=$TMP_FILE_LIST
}

THIS_PATH="$(realpath "$0")"
THIS_DIR="$(dirname "$THIS_PATH")"

append_all_sources_headers "$THIS_DIR/wifibroadcast/src"
append_all_sources_headers "$THIS_DIR/wifibroadcast/executables"

echo "Files found to format = \n\"\"\"\n$FILE_LIST\n\"\"\""

# Checks for clang-format issues and returns error if they exist
function check_warning(){
  clang-format --dry-run --Werror --verbose -i --style=file $FILE_LIST

  if [ "$?" -eq "0" ]; then
    echo "Everything formatted correctly"
  else
    echo "There are formatting errors ! Please fix first."
    exit 1
  fi
}

# fixes any issues (re-formats everything)
function fix_warnings() {
    clang-format --verbose -i --style=file $FILE_LIST
}

if [ "$1" == "f" ]; then
   echo "Fixing warnings"
   fix_warnings
else
  echo "Checking warnings"
  check_warning
fi