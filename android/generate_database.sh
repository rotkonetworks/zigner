#!/bin/bash

RELEASE_PATH=../rust/database/database_cold_release
DBPATH=./src/main/assets/Database

set -e

pushd ../rust/db_handling

cargo run --locked --features active --bin make_cold_release

popd

# Move database to assets

echo "Re-creating $DBPATH"
rm -rf $DBPATH
mkdir -p $DBPATH

echo "Copying DB from $RELEASE_PATH to $DBPATH"
cp -R $RELEASE_PATH/. $DBPATH
