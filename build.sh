#!/bin/bash

list="x86_64-linux-gnu-gcc i686-linux-gnu-gcc arm-linux-gnueabi-gcc aarch64-linux-gnu-gcc sparc64-linux-gnu-gcc mips-linux-gnu-gcc powerpc-linux-gnu-gcc"
declare -A alias=( [i686-linux-gnu-gcc]=x86-linux-gnu-gcc )
declare -a compilers

IFS= read -ra candidates <<< "$list"

# first select platforms/compilers
for cc in ${candidates[@]}
do
	# check compiler first
	if ! command -v $cc &> /dev/null; then
		continue
	fi
	
	if [[ $# == 0 ]]; then
		compilers+=($cc)
		continue
	fi

	for arg in $@
	do
		if [[ ${alias[$cc]:-$cc} =~ $arg ]]; then 
			compilers+=($cc)
		fi
	done
done

# then iterate selected platforms/compilers
for cc in ${compilers[@]}
do
	IFS=- read -r platform host dummy <<< ${alias[$cc]:-$cc}

	make clean && make CC=$cc GPP=${cc/gcc/g++}
		
	mkdir -p targets/$host/$platform
	cp source/build64//lib*.a $_
done

#mkdir -p targets/include
cp -ur include/ targets/


