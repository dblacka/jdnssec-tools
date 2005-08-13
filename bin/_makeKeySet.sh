#! /bin/sh

thisdir=`dirname $0`
basedir=`cd $thisdir/..; pwd`

ulimit -n `ulimit -H -n`

if [ x$JAVA_HOME = x ]; then
	JAVA_HOME=/usr/local/jdk1.3
	export JAVA_HOME
fi

LD_LIBRARY_PATH=${basedir}/obj:${LD_LIBRARY_PATH}
export LD_LIBRARY_PATH

# set the classpath
CLASSPATH=\
$JAVA_HOME/jre/lib/rt.jar:\
$basedir/obj/classes:\
$basedir/lib/dnsjava.jar:\
$basedir/lib/protomatter-1.1.5.jar:\
$basedir/lib/jdom-B6.jar:\
$basedir/lib/jce1_2_1.jar

export CLASSPATH

exec $JAVA_HOME/bin/java -Xmx64m com.nsi.dnssec.cl.MakeKeySet "$@"
