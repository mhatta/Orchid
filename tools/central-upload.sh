#!/bin/sh
# Upload a bundle made by "./gradlew centralBundle" to the Maven Central
# Portal, then wait until the Portal has validated it.
#
#   tools/central-upload.sh build/distributions/orchid-2.4.0-bundle.zip
#
# The deployment is USER_MANAGED: after validation, check it and press
# "Publish" at https://central.sonatype.com/publishing/deployments.  Set
# PUBLISHING_TYPE=AUTOMATIC to publish as soon as it validates.
#
# Credentials: a Portal user token (not the login password), from
# CENTRAL_USERNAME / CENTRAL_PASSWORD or, failing that, from
# mavenCentralUsername / mavenCentralPassword in ~/.gradle/gradle.properties.
set -eu

bundle=${1:?usage: $0 orchid-<version>-bundle.zip}
[ -f "$bundle" ] || { echo "$0: $bundle: no such file" >&2; exit 1; }

prop() {
	f="${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties"
	[ -f "$f" ] && sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$f" | tail -n 1
}
user=${CENTRAL_USERNAME:-$(prop mavenCentralUsername)}
pass=${CENTRAL_PASSWORD:-$(prop mavenCentralPassword)}
[ -n "$user" ] && [ -n "$pass" ] || { echo "$0: no Central Portal token (see the comment at the top)" >&2; exit 1; }

api=${CENTRAL_API:-https://central.sonatype.com/api/v1/publisher}
auth="Authorization: Bearer $(printf '%s:%s' "$user" "$pass" | base64 | tr -d '\n')"
name=$(basename "$bundle" .zip)

id=$(curl --fail-with-body -sS -X POST -H "$auth" \
	-F "bundle=@$bundle;type=application/octet-stream" \
	"$api/upload?name=$name&publishingType=${PUBLISHING_TYPE:-USER_MANAGED}")
echo "deployment $id"

while :; do
	status=$(curl --fail-with-body -sS -X POST -H "$auth" "$api/status?id=$id")
	state=$(printf '%s' "$status" | sed -n 's/.*"deploymentState"[[:space:]]*:[[:space:]]*"\([A-Z_]*\)".*/\1/p')
	echo "state: $state"
	case "$state" in
	VALIDATED)
		echo "Validated.  Check it and press Publish: https://central.sonatype.com/publishing/deployments"
		exit 0 ;;
	PUBLISHING|PUBLISHED)
		exit 0 ;;
	FAILED)
		printf '%s\n' "$status" >&2
		exit 1 ;;
	esac
	sleep 10
done
