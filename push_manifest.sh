#!/bin/bash
set -e

UPLOAD_IMAGE="false"

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -i | --image-upload )
            UPLOAD_IMAGE="true"
            echo "Upload image: ${UPLOAD_IMAGE}"
            ;;
        * )
            break;;
    esac
    shift
done

IMAGE_NAME=${1:-}
IMAGE_TAG=${2:-latest}
DOCKER_REPOSITORY=${3:-quay.io/cilium}
DOCKER_REGISTRY=${4:-}
IMAGE_ARCH=("amd64" "arm64")

if [ -z "${IMAGE_NAME}" ]
then
  echo "Please specify a image name!"
  echo -e "\nUsage::\n\tpush_manifest.sh IMAGE_NAME [IMAGE_TAG] [DOCKER_REPOSITORY] [DOCKER_REGISTRY]"
  echo -e "\nExample::\n\tpush_manifest.sh cilium-envoy latest"
  exit 1
fi

export DOCKER_CLI_EXPERIMENTAL=enabled

if [ "${UPLOAD_IMAGE}" = "true" ]; then
    for arch in "${IMAGE_ARCH[@]}"
    do
	docker push ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-${arch}
    done
fi

docker manifest create --amend ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG} \
	${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-amd64 \
	${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-arm64

docker manifest push ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}
