#!/bin/sh

#
# ARG[] tells us files to work on
#
# This translates HTML 4.01 defined character entities to their UNICODE
# equivalents so that e.g.  Netscape 4.* can show them.
#

while [ -n "$1" -a -f "$1" ]
do
    x="$1"
    shift || break

    echo -n "$x "

#  cat $x | \
#  sed	-e 's/&hellip;/\&#8230/g'	\
#	-e 's/&fnof;/\&#402;/g' 	\
#	-e 's/&Alpha;/\&#913;/g'	\
#	-e 's/&Beta;/\&#914;/g' 	\
#	-e 's/&Gamma;/\&#915;/g'	\
#	-e 's/&Delta;/\&#916;/g'	\
#	-e 's/&Epsilon;/\&#917;/g'	\
#	-e 's/&Zeta;/\&#918;/g' 	\
#	-e 's/&Eta;/\&#919;/g'  	\
#	-e 's/&Theta;/\&#920;/g'	\
#	-e 's/&Iota;/\&#921;/g' 	\
#	-e 's/&Kappa;/\&#922;/g'	\
#	-e 's/&Lambda;/\&#923;/g'	\
#	-e 's/&Mu;/\&#924;/g'		\
#	-e 's/&Nu;/\&#925;/g'		\
#	-e 's/&Xi;/\&#926;/g'		\
#	-e 's/&Omicron;/\&#927;/g'	\
#	-e 's/&Pi;/\&#928;/g'		\
#	-e 's/&Rho;/\&#929;/g'		\
#	-e 's/&Sigma;/\&#931;/g'	\
#	-e 's/&Tau;/\&#932;/g'		\
#	-e 's/&Upsilon;/\&#933;/g'	\
#	-e 's/&Phi;/\&#934;/g'		\
#	-e 's/&Chi;/\&#935;/g'		\
#	-e 's/&Psi;/\&#936;/g'		\
#	-e 's/&Omega;/\&#937;/g'	\
#	-e 's/&alpha;/\&#945;/g'	\
#	-e 's/&beta;/\&#946;/g'		\
#	-e 's/&gamma;/\&#947;/g'	\
#	-e 's/&delta;/\&#948;/g'	\
#	-e 's/&epsilon;/\&#949;/g'	\
#	-e 's/&zeta;/\&#950;/g'		\
#	-e 's/&eta;/\&#951;/g'		\
#	-e 's/&theta;/\&#952;/g'	\
#	-e 's/&iota;/\&#953;/g'		\
#	-e 's/&kappa;/\&#954;/g'	\
#	-e 's/&lambda;/\&#955;/g'	\
#	-e 's/&mu;/\&#956;/g'		\
#	-e 's/&nu;/\&#957;/g'		\
#	-e 's/&xi;/\&#958;/g'		\
#	-e 's/&omicron;/\&#959;/g'	\
#	-e 's/&pi;/\&#960;/g'		\
#	-e 's/&rho;/\&#961;/g'		\
#	-e 's/&sigmaf;/\&#962;/g'	\
#	-e 's/&sigma;/\&#963;/g'	\
#	-e 's/&tau;/\&#964;/g'		\
#	-e 's/&upsilon;/\&#965;/g'	\
#	-e 's/&phi;/\&#966;/g'		\
#	-e 's/&chi;/\&#967;/g'		\
#	-e 's/&psi;/\&#968;/g'		\
#	-e 's/&omega;/\&#969;/g'	\
#	-e 's/&thetasym;/\&#977;/g'	\
#	-e 's/&upsih;/\&#978;/g'	\
#	-e 's/&piv;/\&#982;/g'		\
#	-e 's/&bull;/\&#8226;/g'	\
#	-e 's/&prime;/\&#8242;/g'	\
#	-e 's/&Prime;/\&#8243;/g'	\
#	-e 's/&oline;/\&#8254;/g'	\
#	-e 's/&frasl;/\&#8260;/g'	\
#	-e 's/&weierp;/\&#8472;/g'	\
#	-e 's/&image;/\&#8465;/g'	\
#	-e 's/&real;/\&#8476;/g'	\
#	-e 's/&trade;/\&#8482;/g'	\
#	-e 's/&alefsym;/\&#8501;/g'	\
#	-e 's/&larr;/\&#8592;/g'	\
#	-e 's/&uarr;/\&#8593;/g'	\
#	-e 's/&rarr;/\&#8594;/g'	\
#	-e 's/&darr;/\&#8595;/g'	\
#	-e 's/&harr;/\&#8596;/g'	\
#	-e 's/&crarr;/\&#8629;/g'	\
#	-e 's/&lArr;/\&#8656;/g'	\
#	-e 's/&uArr;/\&#8657;/g'	\
#	-e 's/&rArr;/\&#8658;/g'	\
#	-e 's/&dArr;/\&#8659;/g'	\
#	-e 's/&hArr;/\&#8660;/g'	\
#	-e 's/&forall;/\&#8704;/g'	\
#	-e 's/&part;/\&#8706;/g'	\
#	-e 's/&exist;/\&#8707;/g'	\
#	-e 's/&empty;/\&#8709;/g'	\
#	-e 's/&nabla;/\&#8711;/g'	\
#	-e 's/&isin;/\&#8712;/g'	\
#	-e 's/&notin;/\&#8713;/g'	\
#	-e 's/&ni;/\&#8715;/g'  	\
#	-e 's/&prod;/\&#8719;/g'	\
#	-e 's/&sum;/\&#8721;/g' 	\
#	-e 's/&minus;/\&#8722;/g'	\
#	-e 's/&lowast;/\&#8727;/g'	\
#	-e 's/&radic;/\&#8730;/g'	\
#	-e 's/&prop;/\&#8733;/g'	\
#	-e 's/&infin;/\&#8734;/g'	\
#	-e 's/&ang;/\&#8736;/g' 	\
#	-e 's/&and;/\&#8743;/g' 	\
#	-e 's/&or;/\&#8744;/g'  	\
#	-e 's/&cap;/\&#8745;/g' 	\
#	-e 's/&cup;/\&#8746;/g' 	\
#	-e 's/&int;/\&#8747;/g' 	\
#	-e 's/&there4;/\&#8756;/g'	\
#	-e 's/&sim;/\&#8764;/g' 	\
#	-e 's/&cong;/\&#8773;/g'	\
#	-e 's/&asymp;/\&#8776;/g'	\
#	-e 's/&ne;/\&#8800;/g'  	\
#	-e 's/&equiv;/\&#8801;/g'	\
#	-e 's/&le;/\&#8804;/g'  	\
#	-e 's/&ge;/\&#8805;/g'  	\
#	-e 's/&sub;/\&#8834;/g' 	\
#	-e 's/&sup;/\&#8835;/g' 	\
#	-e 's/&nsub;/\&#8836;/g'	\
#	-e 's/&sube;/\&#8838;/g'	\
#	-e 's/&supe;/\&#8839;/g'	\
#	-e 's/&oplus;/\&#8853;/g'	\
#	-e 's/&otimes;/\&#8855;/g'	\
#	-e 's/&perp;/\&#8869;/g'	\
#	-e 's/&sdot;/\&#8901;/g'	\
#	-e 's/&lceil;/\&#8968;/g'	\
#	-e 's/&rceil;/\&#8969;/g'	\
#	-e 's/&lfloor;/\&#8970;/g'	\
#	-e 's/&rfloor;/\&#8971;/g'	\
#	-e 's/&lang;/\&#9001;/g'	\
#	-e 's/&rang;/\&#9002;/g'	\
#	-e 's/&loz;/\&#9674;/g'		\
#	-e 's/&spades;/\&#9824;/g'	\
#	-e 's/&clubs;/\&#9827;/g'	\
#	-e 's/&hearts;/\&#9829;/g'	\
#	-e 's/&diams;/\&#9830;/g'	\
#	-e 's/&OElig;/\&#338;/g'	\
#	-e 's/&oelig;/\&#339;/g'	\
#	-e 's/&Scaron;/\&#352;/g'	\
#	-e 's/&scaron;/\&#353;/g'	\
#	-e 's/&Yuml;/\&#376;/g'		\
#	-e 's/&circ;/\&#710;/g' 	\
#	-e 's/&tilde;/\&#732;/g'	\
#	-e 's/&ensp;/\&#8194;/g'	\
#	-e 's/&emsp;/\&#8195;/g'	\
#	-e 's/&thinsp;/\&#8201;/g'	\
#	-e 's/&zwnj;/\&#8204;/g'	\
#	-e 's/&zwj;/\&#8205;/g' 	\
#	-e 's/&lrm;/\&#8206;/g' 	\
#	-e 's/&rlm;/\&#8207;/g' 	\
#	-e 's/&ndash;/\&#8211;/g'	\
#	-e 's/&mdash;/\&#8212;/g'	\
#	-e 's/&lsquo;/\&#8216;/g'	\
#	-e 's/&rsquo;/\&#8217;/g'	\
#	-e 's/&sbquo;/\&#8218;/g'	\
#	-e 's/&ldquo;/\&#8220;/g'	\
#	-e 's/&rdquo;/\&#8221;/g'	\
#	-e 's/&bdquo;/\&#8222;/g'	\
#	-e 's/&dagger;/\&#8224;/g'	\
#	-e 's/&Dagger;/\&#8225;/g'	\
#	-e 's/&permil;/\&#8240;/g'	\
#	-e 's/&lsaquo;/\&#8249;/g'	\
#	-e 's/&rsaquo;/\&#8250;/g'	\
#	-e 's/&euro;/\&#8364;/g'	\
#	-e 's/&dd;/--/g'		\
#	-e 's/&ddash;/--/g'		\
#	-e 's/&PGBREAK;//g'		\
#	-e 's/&pgbreak;//g'		\
#			|		\
#
  cat $x | \
  sed	-e 's/&euro;/\&#8364;/g'	\
	-e 's/&dd;/--/g'		\
	-e 's/&ddash;/--/g'		\
	-e 's/&PGBREAK;//g'		\
	-e 's/&pgbreak;//g'		\
			|		\
	tidy -i -u -n -q |		\
  perl -ne 's/<LINK rel="STYLESHEET" type="text\/css" href="zmanual.css">/<!--#include file="zmanual.css" -->/o; 
       s/("[^.]*)\.html#/$1.shtml#/go;
       s/("[^.]*)\.html"/$1.shtml"/go;
       print;'				\
					\
	> $x.new

	# mv $x $x.old
        rm -f $x
  	y=`basename $x .html`.shtml
	mv $x.new $y

done

echo

#	-e 's/&ndash;/\&#8211;/g'	\
#	-e 's/&mdash;/\&#8212;/g'	\
#	-e 's/&ndash;/-/g'	\
#	-e 's/&mdash;/--/g'	\
