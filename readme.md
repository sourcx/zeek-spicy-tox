# zeek-spicy-tox

<b>THIS SOFTWARE IS NOT FINISHED</b>

This is a Tox parser for Zeek based on https://www.youtube.com/watch?v=oJprmlB3eNo.

It is not finished. You should at least try to create better signatures or make sense of the packet sizes in the system messages.
Also, in main.zeek there is a filter that drops all system messages of length 33. This is arbitrary just to show how that could work.

## Compile and test

```
cd build
cmake ..
cmake --build .
cd ../tests
btest
```

Then I just use this one-liner in the build/ dir everytime after changing code: `cd ../build && cmake --build . && cd ../tests && btest`

The tests verify that the resulting output is the same as `tests/baseline/analyzer.basic` using zeek-diff.
After you run the tests you can check the actual output in `tests/.tmp/analyzer.basic/`.
If something goes wrong you will see stuff in .stdout or .stderr.

## Tox documentation

- https://zetok.github.io/tox-spec/

## PCAP sources

- tox3.pcap (self recorded)
