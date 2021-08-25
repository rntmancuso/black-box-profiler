#!/bin/bash
#This code runs all sdvbs benchmarks except multi-ncat which takes too long
#Writing a Flag indicating Run in progress

bms="mser disparity localization sift stitch svm tracking texture_synthesis"
runs=1
sizes="sqcif qcif cif vga"
topdir=$(pwd)
prof=~/bb_profiler/profiler/profiler
outdir=~/profiles

# Enter in the benchmarks directory
cd benchmarks/

for b in $bms
do
    # Skip multi_ncut (too long)
    if [ "$b" == "multi_ncut" ]
    then
	continue
    fi
    #       cd $pwd
    cd $b/data/
    dataset=$(ls .)

    sym=$(cat ../prof_symbol.txt)

    for d in $sizes
    do
	if [ "$b" == "sift" ]
	then
		if [ "$d" == "vga" ]
		then
			continue
		fi
	fi

	# Skip fullhd (too long)
	if [ "$d" == "fullhd" ]
	then
	    continue
	fi

	echo "RANKING $b [$d]"
	profile=$outdir/"$b"_"$d".prof
	rankfile=$outdir/"$b"_"$d"_ranking.txt

	cd $d
	for i in $(seq $runs)
	do
	    $prof -i $profile -q -n0 -r -s $sym ./$b .
	done
	cd ..
    done
    cd ../..
    done
