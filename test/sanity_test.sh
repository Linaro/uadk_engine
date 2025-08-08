#!/bin/bash

sudo chmod 666 /dev/hisi_*

TEST_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

version=$(openssl version)
echo $version

# Extract the major version number (e.g., "3") from the version string
major_version=$(echo $version | awk -F'[ .]' '{print $2}')
echo "OpenSSL major version is "$major_version

UACCE_DIR="/sys/class/uacce"
api_version=""

for device_dir in "$UACCE_DIR"/*; do
    if [ -d "$device_dir" ]; then
        device_name=$(basename "$device_dir")

        api_file="$device_dir/api"
        if [ -f "$api_file" ]; then
            api_version=$(cat "$api_file")
	    break
        fi
    fi
done

test_provider_v2() {
	$TEST_SCRIPT_DIR/sanity_test_provider.sh
	exit
}

test_provider_v3() {
	exit
}

test_engine() {
	$TEST_SCRIPT_DIR/sanity_test_engine.sh
	exit
}

if [ $# -eq 0 ]; then
	# if no para, check openssl version only
	if ((major_version >= 3)); then
		if [ "$api_version" == "hisi_qm_v2" ]; then
			echo "Testing hisi_qm_v2 provider"
			test_provider_v2
		elif [ "$api_version" == "hisi_qm_v3" ]; then
			echo "Testing hisi_qm_v3 provider"
		fi
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
