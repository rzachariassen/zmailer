#! /usr/bin/perl
#
#  Removes SGML tags such as <tag> and </tag>
#  
#  ARGS:  tag name (without <, /, and >) and a file name 
#

$fname = $ARGV[1];
$left='<';
$right='>';
$slash='/';
$start_tag =  $left.$ARGV[0].$right; 
$end_tag =  $left.$slash.$ARGV[0].$right;

open (INFILE, "< $fname") or die "Open of file $fname failed.";
kill_tags ($start_tag, $end_tag);

exit 0;

##########################################################

sub kill_tags ($start_tag, $end_tag) {

#    print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

    while (<INFILE>) {
   	s/$start_tag//g;
	s/$end_tag//g;
	print $_; 
	}
}

##########################################################
