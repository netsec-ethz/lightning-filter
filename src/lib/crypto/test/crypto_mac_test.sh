# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 ETH Zurich

# number of test cases per block size
noTests=10

# e.g., minNoBlock=1 and maxNoBlock=4 --> tests 1, 2, 3 and 4 blocks
minNoBlocks=2
maxNoBlocks=2

error=0
printInfo=0

for j in $(seq $minNoBlocks $maxNoBlocks)
do
	successful=0
	noBytes=$((j*16))
	if [[ $printInfo -eq 1 ]]; then
		echo "Testing $j blocks.."
	fi
	for i in $(seq 1 $noTests)
	do	
		#key=`hexdump -n 16 -e '4/4 "%08X"' /dev/urandom`
		key=`openssl rand -hex 16`
		#randInput=`hexdump -n $noBytes -e '4/4 "%08X"' /dev/random	`
		randInput=`openssl rand -hex $noBytes`
		refSolution=`echo $randInput | perl -ne 's/([0-9a-f]{2})/print chr hex $1/gie' | openssl enc -e -aes-128-cbc -K $key -iv 00000000000000000000000000000000 -nopad | hexdump -e '16/1 "%02X"' | tail -c 32` 
		implSolution=`./crypto_mac_test $key $randInput`

		if [ "$refSolution" = "$implSolution" ]
		then
			successful=$((successful+1))
		else
			error=$((error+1))
			echo "ERROR: The following test case failed: "	
			echo "key: $key"
			echo "input: $randInput"
			echo "reference solution: $refSolution"
			echo "output: $implSolution"
		fi
	done

	if [[ $printInfo -eq 1 ]]; then
		echo "$successful / $nTests successful for $j blocks"
	fi
done


if [[ $error -eq 0 ]]; then
	exit 0
else
	exit 1
fi