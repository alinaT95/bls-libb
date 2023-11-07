#!/bin/sh
find . -name tests -type d -print0 | xargs -0 rm -rf
find ./ -name Cargo.toml -type f -print0 | xargs -0 sed -i -E "s/git = (\"|')(ssh|https):\/\/(git@)?github.com\/tonlabs\/ever-([A-Za-z0-9_-]*)-private(\.git)?/git =\1https:\/\/github.com\/tonlabs\/ever-\4\5/g"

rm -f *.sh
