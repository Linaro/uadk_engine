#!/bin/bash

set -x
sudo chmod 666 /dev/hisi_*

TEST_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

version=$(openssl version)
echo $version

# Extract the major version number (e.g., "3") from the version string
major_version=$(echo $version | awk -F'[ .]' '{print $2}')
echo "OpenSSL major version is "$major_version

test_provider() {
	$TEST_SCRIPT_DIR/sanity_test_provider.sh
	exit
}

test_engine() {
	$TEST_SCRIPT_DIR/sanity_test_engine.sh
	exit
}

if [ $# -eq 0 ]; then
	# if no para, check openssl version only
	if ((major_version >= 3)); then
		test_provider
	fi

	if [[ $version =~ "1.1.1" ]]; then
		test_engine
	fi
fi

if [[ $1 =~ "engine" ]]; then
	test_engine
fi

if [[ $1 =~ "provider" ]]; then
	test_provider
fi
