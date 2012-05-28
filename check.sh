#!/bin/sh
export PATH=$PWD:$PATH

if [ -z "$QUIET" ] ; then
    QUIET=0
fi

GREP=$(which grep)
if [ -z "$GREP" -o ! -x $GREP ] ; then
    echo Couldn\'t find a working grep program, sorry.
    exit 1
elif [ $QUIET -ne 1 ] ; then
    echo Using grep $GREP
fi

if [ $# -lt 1 ] ; then
    echo Parameter: $0 '<filename>'
    exit 2
elif [ $QUIET -ne 1 ] ; then
    echo Checking files starting with $1
fi

BASEFILE=$1
shift

FILELIST=$(ls $BASEFILE[0123456789]* | $GREP -v 'md5' | $GREP -v 'sha')

RESULT=0
for file in $FILELIST ; do
        if [ $QUIET -ne 1 ] ; then
                echo -e "\tChecking $file"
        fi
        LEFT_MD5=$(md5sum $file | awk '{print $1}')
        RIGHT_MD5=$(md5sum tests/$file | awk '{print $1}')
        LEFT_SHA1=$(sha1sum $file | awk '{print $1}')
        RIGHT_SHA1=$(sha1sum tests/$file | awk '{print $1}')
        if [ "$LEFT_MD5" != "$RIGHT_MD5" ] ; then
                echo md5sum - new \"$LEFT_MD5\" reference \"$RIGHT_MD5\"
                RESULT=1
        fi
        if [ "$LEFT_SHA1" != "$RIGHT_SHA1" ] ; then
                echo sha1sum - new \"$LEFT_SHA1\" reference \"$RIGHT_SHA1\"
                RESULT=1
        fi
done

if [ $RESULT -ne 0 ] ; then
    echo One or more comparisons failed.
elif [ $QUIET -ne 1 ] ; then
    echo All okay.
fi

exit $RESULT

