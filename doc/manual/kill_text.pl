#! /usr/bin/perl
#  
#  Removes any text between tags such as <tag> and </tag> as well as the tags.
#  
#  ARGS:  tag name (without <, /, and >) and a file name
#

#$sub_name=$ARGV[0];
$fname = $ARGV[1];
$left='<';
$right='>';
$slash='/';
$start_tag =  $left.$ARGV[0].$right; 
$end_tag =  $left.$slash.$ARGV[0].$right;

$files = join(' ',@ARGV[1]);
foreach $file (split(/ /,$files)) {
    & kill_text ($file, $start_tag, $end_tag);
}
exit 0;

##########################################################

sub kill_text ($file, $start_tag, $end_tag) {

open (INFILE, "< $file") or die "Open of file $file failed.";

#    print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
#    print $_;

#    while (<INFILE>) {
#    print $_;
    undef $/;
    $_=<INFILE>;
    s {$start_tag.*?$end_tag} []gsx;
    print $_;
#    }
}
##########################################################
