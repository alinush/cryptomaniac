#!/bin/bash


CURR_DIR=$(readlink -f $(dirname $0))
CM_BIN=cryptomaniac

bvt_test()
{
	local key=1234567890123456123456789012345612345678901234561234567890123456
	local iv=aaaabbbbccccddddeeeeffff00001111
	local infile=$1
	local outfile=$infile.enc
	
	echo "Starting BVT test with file $0..."
	for mode in "cbc" "ctr"; do
		echo -n " * Encrypting in $mode mode... "
		# Encrypt file
		encrypt_with_cm $infile $outfile $key $iv $mode 1
		if [ $? -ne 0 ]; then
			echo "FAILED!"
			return 0
		fi
		echo "OK!"
	
		# Decrypt file back
		echo -n " * Decrypting back in $mode mode... "
		encrypt_with_cm $outfile $infile.dec $key $iv $mode 0
		if [ $? -ne 0 ]; then
			echo "FAILED!"
			return 0
		fi
		echo "OK"
	
		echo -n " * Comparing initial file to decrypted file... "
		# Compare decrypted file to initial file
		cmp $infile $infile.dec
		if [ $? -ne 0 ]; then
			echo "INCORRECT!"
			return 0
		fi
		
		echo "OK!"
		
		# Remove these files
		rm $outfile $infile.dec
	done
	
	return 1
}

openssl_compat_test() 
{
	
	local key=1234567890123456123456789012345612345678901234561234567890123456
	local iv=aaaabbbbccccddddeeeeffff00001111
	local infile=$1
	
	local cm_enc_outfile=$infile.cm.enc
	local openssl_dec_outfile=$cm_enc_outfile.dec
	
	local openssl_enc_outfile=$infile.openssl.enc
	local cm_dec_outfile=$openssl_enc_outfile.dec
	
	echo "Starting OpenSSL compatibility test with file $0..."
	
	for mode in "cbc" "ctr"; do
		# Encrypt file with CM and decrypting it with OpenSSL
		echo -n " * Encrypting with CM and decrypting with OpenSSL in $mode mode... "
		
		encrypt_with_cm $infile $cm_enc_outfile $key $iv $mode 1
		encrypt_with_openssl $cm_enc_outfile $openssl_dec_outfile $key $iv $mode 0
		if [ $? -ne 0 ]; then
			echo "OpenSSL decryption FAILED!"
			return 0
		fi
		
		cmp $infile $openssl_dec_outfile
		if [ $? -ne 0 ]; then
			echo "INCORRECT decryption!"
			return 0
		else
			echo "OK!"
		fi
		
		# Encrypt file with OpenSSL and decrypt using CM
		echo -n " * Encrypting with OpenSSL and decrypting with CM in $mode mode... "
		
		encrypt_with_openssl $infile $openssl_enc_outfile $key $iv $mode 1
		encrypt_with_cm $openssl_enc_outfile $cm_dec_outfile $key $iv $mode 0
		if [ $? -ne 0 ]; then
			echo "OpenSSL encryption FAILED!"
			return 0
		fi
		
		cmp $infile $cm_dec_outfile
		if [ $? -ne 0 ]; then
			echo "INCORRECT decryption!"
			return 0
		else
			echo "OK!"
		fi
	done
	
	rm $cm_enc_outfile
	rm $cm_dec_outfile
	rm $openssl_enc_outfile
	rm $openssl_dec_outfile
	
	return 1
}

encrypt_with_cm()
{
	local enc=
	
	if [ $6 -eq 1 ]; then
		enc=-e
	else
		enc=-d
	fi
	
	$CURR_DIR/$CM_BIN $1 $2 -k $3 -i $4 -m $5 $enc
	
	return $?
}

encrypt_with_openssl()
{
	local enc=
	local mode=
	
	if [[ $5 == "cbc" ]]; then
		mode=-aes-256-cbc
	elif [[ $5 == "ctr" ]]; then
		mode=-aes-256-ctr 
	fi
	
	if [ $6 -eq 1 ]; then
		enc=-e
	else
		enc=-d
	fi
	
	openssl enc $enc $mode -nosalt -in $1 -out $2 -K $3 -iv $4
	return $?
}

random_file_test()
{
	randfile="randfile"
	
	echo "Starting random file tests..."
	dd if=/dev/urandom of=$randfile bs=$((1024*1024)) count=16 &>/dev/null
	bvt_test $randfile
	if [ $? -ne 1 ]; then
		return 0
	fi
	
	openssl_compat_test $randfile
	if [ $? -ne 1 ]; then
		return 0
	fi
	
	rm $randfile
	return 1
}

# Test like a maniac!!
bvt_test $0
if [ $? -eq 1 ]; then
	echo "BVT passed!"
else
	echo "BVT failed!"
fi

echo
openssl_compat_test $0
if [ $? -eq 1 ]; then
	echo "OpenSSL compatibility test passed!"
else
	echo "OpenSSL compatibility test failed!"
fi

echo
random_file_test
if [ $? -eq 1 ]; then
	echo "Random file test passed!"
else
	echo "Random file test failed!"
fi


