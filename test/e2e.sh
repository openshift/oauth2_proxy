#!/bin/bash -x
set -e

PROJECT_REPO=github.com/openshift/oauth-proxy
DOCKER_REPO=localhost:5000

KUBECONFIG=~/admin.kubeconfig

REV=$(git rev-parse --short HEAD)
TEST_IMAGE=${DOCKER_REPO}/oauth-proxy-${REV}:latest
TEST_DIR=$(pwd)/test
HELLO_PATH=${TEST_DIR}/e2e/hello
HELLO_IMAGE=${DOCKER_REPO}/hello-proxy-${REV}:latest
ORIGIN_BUILD_DIR=/tmp/opbuild
ORIGIN_PATH=${ORIGIN_BUILD_DIR}/src/github.com/openshift/origin

if [ "${1}" == "clusterup" ]; then
	if [ "${2}" != "nobuild" ]; then
		if [ ! -d "${ORIGIN_BUILD_DIR}/src" ]; then
			mkdir -p ${ORIGIN_BUILD_DIR}/src
		fi
		pushd .
		cd /
		GOPATH=${ORIGIN_BUILD_DIR} go get github.com/openshift/origin
		cd ${ORIGIN_PATH}
		# Stabilize on a known working 3.9 commit just for assurance.
		git checkout 126033b
		popd
		GOPATH=${ORIGIN_BUILD_DIR} ${ORIGIN_PATH}/hack/build-go.sh
	fi
	export PATH=${ORIGIN_PATH}/_output/local/bin/linux/amd64/:${PATH}
	openshift version

	# Run bindmountproxy for a non-localhost OpenShift endpoint
	IP=$(openshift start --print-ip)
	docker run --privileged --net=host -v /var/run/docker.sock:/var/run/docker.sock -d --name=bindmountproxy cewong/bindmountproxy proxy ${IP}:2375 $(which openshift)
	sleep 2
	docker_host=tcp://${IP}:2375
	DOCKER_HOST=${docker_host} oc cluster up -e DOCKER_HOST=${docker_host}

	sudo cp /var/lib/origin/openshift.local.config/master/admin.kubeconfig ~/
	sudo chmod 777 ${KUBECONFIG}
	oc login -u developer -p pass
	oc status
fi

# build backend site
go build -o ${HELLO_PATH}/hello_openshift ${PROJECT_REPO}/test/e2e/hello
sudo docker build -t ${HELLO_IMAGE} ${HELLO_PATH}
sudo docker push ${HELLO_IMAGE}

# build oauth-proxy
go build -o ${TEST_DIR}/oauth-proxy
sudo docker build -t ${TEST_IMAGE} ${TEST_DIR}/
sudo docker push ${TEST_IMAGE}

# run test
export TEST_IMAGE TEST_NAMESPACE HELLO_IMAGE KUBECONFIG
go test -v ${PROJECT_REPO}/test/e2e
