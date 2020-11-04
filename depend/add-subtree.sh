#!/bin/bash
# This command pulls the latest updates from the master branch of the subtree and commits them in depend/secp256k1.
# See man git-subtree(1) for more details.
git subtree add --prefix depend/secp256k1 https://github.com/kaspanet/secp256k1.git master --squash
