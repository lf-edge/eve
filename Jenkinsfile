pipeline {
  agent any
  stages {
    stage('eve_and_eden') {
      steps {
        sh '''#!/bin/bash
make build-tools
make HV=kvm eve
evebuildname=$(find ./dist/amd64 | grep kvm-amd64 | grep -o '0.*-kvm-amd64')
eve_tag=${evebuildname%-kvm-amd64}
rm -rf ./eden
git clone https://github.com/lf-edge/eden.git
cd ./eden
make clean
make build
./eden config add default  
./eden config set default --key eve.tag --value=$eve_tag
./eden config set default --key=eve.accel --value=false
make build-tests

./eden test ./tests/workflow
 '''
      }
    }

  }
}
