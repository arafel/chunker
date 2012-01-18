#!/bin/sh
export PATH=$PWD:$PATH

if [ -z "$QUIET" ] ; then
    QUIET=0
fi

DIFF=$(which diff)
if [ -z "$DIFF" -o ! -x $DIFF ] ; then
    echo Couldn\'t find a working diff program, sorry.
    exit 1
elif [ $QUIET -ne 1 ] ; then
    echo Using diff $DIFF
fi

# We specifically want our hexdump, we know it's output.
if [ ! -x ./hexdump ] ; then
    echo Hexdump doesn\'t exist or isn\'t executable
    exit 1
fi

if [ $# -lt 1 ] ; then
    echo Parameter: $0 '<filename>'
    exit 2
elif [ $QUIET -ne 1 ] ; then
    echo Checking files starting with $1
fi

BASEFILE=$1
shift

for hash in $BASEFILE*.md5 $BASEFILE*.sha1 ; do
    ./hexdump $hash > "$hash"sum
done

RESULT=0
for hash in $BASEFILE*sum ; do
    diff $hash tests/$hash
    if [ $? -ne 0 ] ; then
        echo $hash failed comparison.
        RESULT=1
    fi
done

if [ $RESULT -ne 0 ] ; then
    echo One or more comparisons failed.
elif [ $QUIET -ne 1 ] ; then
    echo All okay.
fi

exit $RESULT
