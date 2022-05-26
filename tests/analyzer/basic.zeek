# @TEST-REQUIRES: test -e ${TRACES}/tox3.pcap
# @TEST-EXEC: zeek -Cr ${TRACES}/tox3.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tox.log
#
# @TEST-DOC: Test Tox against Zeek with a small trace.

@load analyzer
