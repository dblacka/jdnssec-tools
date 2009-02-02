#! /bin/bash

./bin/_jdnssec-signzone \
	-3 \
	-A 133:5:RSASHA1-NSEC3 \
	-s 20051021000000 \
	-e 20150420235959 \
	-D test/ \
	-S AABBCCDD \
	--iterations 12 \
	-k Kexample.+133+22088 \
	test/example \
	Kexample.+133+62827
	
