#! /usr/bin/perl
#
#  This program is for auto-translating CF file to SGML markup
#  Can you say:  "Literal Programming" ?
#
#  ARGS: source file names
#  STDOUT: resulting SGML
#
# Lines starting with  '#!'  are ignored.
# Lines starting with  '#|'  are processed for markup text.
# Other lines are placed as is into the <verb> ... </verb> block.
#

$files = join(' ',@ARGV);

printf "\
<appendix>
<sect>Sample Router Configuration Scripts
<p>
Text to be inserted here.
<p>

";

foreach $file (split(/ /,$files)) {
    & readproc ( $file );
}

exit 0;

sub readproc () {
    local ($fname) = @_;
    local ($verbmode, $leadskip, $tailwhite, $delayverb);
    $verbmode = 0;
    $leadskip = 0;
    $delayverb = 0;
    $tailwhite = '';

    open (INFILE, "< $fname") or die "Open of file '$fname' failed: $!";

    $fname =~ s!(.*/)([^/]+)!\2!; # 'basename'

    printf "<sect1>%s\n<p>\n", $fname;

    while (<INFILE>) {
	chomp;
	if (substr($_,0,2) eq '#|') {
	    printf "</verb></tscreen>\n\n" if ($verbmode != 0 && $delayverb == 0);
	    $tailwhite = '';
	    $verbmode = 0;
	    next if (substr($_,0,2) eq '#!');
	    # Several processing steps:
	    # - Remove prefix of "#|" 
	    s/^#\|//;
	#   # - Remove prefix of "#" 
	#   s/^#//;
	#   # - Replace all '&' chars with '&amp;' strings
	#   s/&/&amp;/g;
	    # - Replace all dollar signs with '&dollar;' strings
	    s/\$/&dollar;/g;
	    # - Replace all '<' chars with '&lt;' strings
	    s/</&lt;/g;
	    # - Replace all '>' chars with '&gt;' strings
	    s/>/&gt;/g;
	    # - Fix back '&lt;tt&gt;' into '<tt>'
	    #   (also: </tt> <em> </em> <bf> </bf> <verb> </verb> <x> </x>)
	    s!&lt;tt&gt;!<tt>!g;
	    s!&lt;/tt&gt;!</tt>!g;
	    s!&lt;em&gt;!<em>!g;
	    s!&lt;/em&gt;!</em>!g;
	    s!&lt;bf&gt;!<bf>!g;
	    s!&lt;/bf&gt;!</bf>!g;
	    s!&lt;verb&gt;!<verb>!g;
	    s!&lt;/verb&gt;!</verb>!g;
	    s!&lt;x&gt;!<x>!g;
	    s!&lt;/x&gt;!</x>!g;
	    printf "%s\n",$_;
	    next;
	}
	if ($verbmode == 0) {
	    $verbmode = 1;
	    $leadskip = 1;
	    $delayverb = 1;
	}
	if ($_ =~ /^\s*$/) {
	    next if ($leadskip);
	    $tailwhite .= $_ . "\n";
	    next;
	}
	$leadskip = 0;
	printf "\n<tscreen><verb>\n" if ($delayverb != 0);
	$delayverb = 0;
	
	printf "%s%s\n", $tailwhite, $_;
	$tailwhite = '';
    }
    printf "</verb></tscreen>\n\n" if ($verbmode != 0 && $delayverb == 0);

    close INFILE;
}
