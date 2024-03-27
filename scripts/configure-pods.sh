#!/bin/bash

copyfiles -u 1 -a "initial-pod-data/**/*" pods/example
copyfiles -u 4 test/assets/webIdProfiles/noOidcIsser/* pods/example2/profile/
copyfiles -u 4 test/assets/webIdProfiles/invalidWebId/* pods/invalidWebId/profile/
cp  test/assets/webIdProfiles/verifiable-example/profile/* pods/verifiable-example/profile/
cp  test/assets/webIdProfiles/verifiable-example/data/* pods/verifiable-example/
