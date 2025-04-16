#!/usr/bin/env bash

case_name=$1

if [ -z "$1" ]; then
  echo "Provide test case name as the first argument."
  exit 1
fi

default_test_data='null'

script_directory=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if ! [ -d "$script_directory/$case_name" ]; then
  mkdir "$script_directory"/"$case_name"
fi

if ! [ -f "$script_directory/$case_name/input.json" ]; then
  echo $default_test_data > "$script_directory/$case_name/input.json"
fi

if ! [ -f "$script_directory/$case_name/expected_description.json" ]; then
  echo $default_test_data > "$script_directory/$case_name/expected_description.json"
fi

if ! [ -f "$script_directory/$case_name/expected_fields.json" ]; then
  echo $default_test_data > "$script_directory/$case_name/expected_fields.json"
fi