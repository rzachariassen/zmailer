#!/usr/bin/perl -awnl

#
#
#
#
#

BEGIN {
    my($i,$j,$num,@octets);
    for($i=32,$j=0;$i>=0;$i--,$j++) {
	$num=((-1)<<$j);
	@octets=unpack("C4",pack("L",$num));
	$convert{join(".",@octets)}=$i;
    }
}
/^direct/ && do {$offset=0;};
/^sockd/ && do {$offset=1;};
(/^direct/ || /^sockd/) && do {
    $a=pack("C4",split(/\./,$F[$offset+1]));
    $al=unpack("L",$a);
    $b=pack("C4",split(/\./,$F[$offset+2]));
    $bl=unpack("L",$b);
#    print("$al $bl");
    $c=join(".",unpack("C4",pack("L",$al&$bl)));
    $d=$convert{$F[$offset+2]};
    print("$c/$d	smtp!");
}
