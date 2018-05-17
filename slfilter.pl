#! /usr/bin/perl -w

# slfilter.pl
#
# syslog listener and display with a simple filtering option
#
# 2010-03-17 initial version
#
# 2010-03-23 rudimentary filter parsing seems to be working;
#		history deletion;
#		priority and facility parsing;
#		width resize works
#
# 2010-03-24 search filter AND and NOT operators work now
#
# 2010-03-26 font scaling added;
#		output window resizing behaving slightly better;
#		started using global config hash
#
# 2010-03-27 altered field highlighting;
#		option to enable/disable display of facility & priority
#
# 2010-03-28 window resize keeps visibility at the end of the output;
#		Quit & Options buttons added;
#		default listen IP now 0.0.0.0;
#		resize works perfectly now (put frames in a grid);
#		option for wrapping text or not
#		option to hide bulky top frame

#
# synopsis:
#
#		*listen on 515/udp for syslog messages
#		*display new messages on the fly if they match the current filter
#		*colorize based on priority and/or other factors
#		*Allow ORing and ANDing in the search filter
#		save/export log entries?
#		option for udp listener, tcp listener, network sniffing?
#
#
# does not handle large volumes so well due to the implementation of using a Tk timer
#
# create default config file if one does not exist; write any changes on exit
# show local eventlog/syslog option
# listenip pulldown; listen port option; history length scale
# option to accept messages only from specific hosts



use strict;
use Tk;
require Tk::ROText;
use IO::Socket;
use IO::Select;

use vars qw(%CONF $fhash);

$| = 1; # autoflush output

# variables
my $filter = '';
$fhash = {};

%CONF = (
	'LISTENIP' => '0.0.0.0',
	'LISTENPORT' => '514',
	'LISTENPROTO' => 'udp',
	'HISTORY' => 100,
	'BG_MAIN' => 'black',				# main window background color
	'BG_FRAME' => '#222222',		# frames inside main window background color
	'DISPLAYPRI' => 0,
	'WRAPTEXT' => 1,						# wrap text in the output window
	'HIDDEN' => 0,							# never change; option for hiding top area
);


# facility map
my @facilities = qw(kern user mail daemon auth syslogd lpr news uucp clock auth ftp ntp audit alert clock local0 local1 local2 local3 local4 local5 local6 local7);
my @priorities = qw(emergency alert critical error warning notice info debug);


# start listener
my $sock_server = udpListener($CONF{'LISTENIP'}, $CONF{'LISTENPORT'});
my $selector = IO::Select->new($sock_server);


# create main window
my $mw = MainWindow->new;
# set title of main window
$mw->title("SLFilter - Syslog Listener");


# configure main window options
$mw->configure(
	-relief => "sunken",
	-bg => $CONF{BG_MAIN},
	#-padx => 10,
	#-pady => 10
);
$mw->minsize(650,250);
#$mw->optionAdd('*font', 'Helvetica 8');


################################################################################
#  Frames
################################################################################

# top frame inside main window
my $topwin = $mw->Frame(
#	-width => 650,
	-padx => 5,
	-pady => 5,
	-bg => $CONF{BG_FRAME}
)->pack(-fill => "x", -expand => 1, -anchor => "n");

my $hidewin = $mw->Frame(
	-padx => 5,
	-pady => 5,
	-bg => $CONF{BG_FRAME}
)->pack(-fill => "x", -expand => 1, -anchor => "n");

# bottom frame inside main window
my $botwin = $mw->Frame(
	-padx => 0,
	-pady => 0,
	-bg => $CONF{BG_FRAME},
)->pack(-fill => "both", -expand => 1, -anchor => "n", -side => "top");

################################################################################
#  Widgets
################################################################################

# label for filter string input
my $label_filter = $topwin->Label(
	-text => 'Filter String:',
	-fg => 'white',
	-bg => $CONF{BG_FRAME}
);
# create an input field for filtering
my $entry_filter = $topwin->Entry(
	-text => '',
	-bg => 'white',
	-width => 40
);
# create an input field which shows the currently applied filter
my $label_filterapplied = $hidewin->Label(
	-text => 'Current Filter: <none>',
	-fg => 'white',
	-bg => $CONF{BG_FRAME},
);

# create the main output window
my $text_output = $botwin->Scrolled('ROText',
	-font => 'Fixed 8 normal',
	-scrollbars => 'osoe',
	-bg => '#333333',
	-fg => '#F0F0F0',
	-width => 132,
	#-height => 40,
)->pack(-anchor => "n", -fill => "both", -expand => 1);
# tags for altering text in the output window
$text_output->tagConfigure("red", -foreground => 'red');
$text_output->tagConfigure("green", -foreground => 'green');
$text_output->tagConfigure("blue", -foreground => '#8888F0');
$text_output->tagConfigure("purple", -foreground => '#F044F0');
$text_output->tagConfigure("white", -foreground => 'white');
$text_output->tagConfigure("orange", -foreground => 'orange');
$text_output->tagConfigure("yellow", -foreground => 'yellow');
$text_output->tagConfigure("bold", -font => 'Helvetica 8 bold');


# create the 'Apply Filter' button
my $button_apply = $topwin->Button(
    -text => 'Apply Filter',
    -font => 'fixed 6 normal',
    -command => sub {
    	print STDOUT "'Apply Filter' button pressed\n";
    	$filter = $entry_filter->get;
    	# parse the filter string
    	$fhash = {};
			my @words = split(/ +/, $filter);
			for (my $i = 0; $i <= $#words; $i++) {
				my $word = $words[$i];
				if ($word eq "NOT") {
					$fhash->{$words[$i+1]} = 'NOT';
					$i += 1;
				} elsif ($word eq "AND") {
					$fhash->{$words[$i-1]} = 'AND';
					$fhash->{$words[$i+1]} = 'AND';
					$i += 1;
				} else {
					$fhash->{$word} = 'OR';
				}
			}
    	$label_filterapplied->configure( -text => "Curent Filter: \'$filter\'" );
			$text_output->insert('end', '-' x 60 . "\n", 'red');
			$text_output->insert('end', "  FILTER APPLIED: ", 'red');
			$text_output->insert('end', "$filter\n");
			$text_output->insert('end', '-' x 60 . "\n", 'red');
			$text_output->see('end');
    }
);

my $button_clearfilter = $topwin->Button(
    -text    => 'Clear Filter',
    -font => 'Fixed 6 normal',
    -command => sub {
    	print STDOUT "'Clear Filter' button pressed\n";
  		$filter = "";
  		$fhash = {};
    	$label_filterapplied->configure( -text => "Current Filter: <none>" );
			$text_output->insert('end', '-' x 60 . "\n", 'green');
			$text_output->insert('end', "  FILTER CLEARED\n", 'green');
			$text_output->insert('end', '-' x 60 . "\n", 'green');
			$text_output->see('end');
    }
);
my $button_clearoutput = $topwin->Button(
    -text    => 'Clear Output',
    -font => 'Fixed 6 normal',
    -command => sub {
    	print STDOUT "'Clear Output' button pressed\n";
    	$text_output->Contents( "" );
			$text_output->see('end');
    }
)->pack(-anchor => 'center');


my $button_options = $topwin->Button(
    -text    => 'Options',
    -font => 'Fixed 6 normal',
    -command => sub {
    	print STDOUT "'Options' button pressed\n";
    }
)->pack(-anchor => 'center');

my $button_quit = $topwin->Button(
    -text    => 'Quit!',
    -font => 'Fixed 6 normal',
    -bg => '#884444',
    -fg => 'white',
    -activeforeground => 'white',
    -activebackground => '#995555',
    -command => sub {
    	print STDOUT "'Quit' button pressed\n";
    	exit;
    }
)->pack(-anchor => 'center');


my $button_toggledisplay = $hidewin->Button(
	-text => '^^^',
	-font => 'Fixed 6 normal',
);
$button_toggledisplay->configure(
	-command => sub {
		unless ($CONF{'HIDDEN'}) {
			$mw->gridForget($topwin);
			$CONF{HIDDEN} = 1;
			$button_toggledisplay->configure(-text => '>>>');
		} else {
			$topwin->grid(-row => 0, -column => 0, -sticky => "ew");
			$CONF{HIDDEN} = 0;
			$button_toggledisplay->configure(-text => '^^^');
		}
	}
);


my $label_listeninfo = $hidewin->Label(
	-text => "Listening on $CONF{LISTENIP}:$CONF{LISTENPORT}",
	-font => 'Fixed 6 normal',
	-fg => 'green',
	-bg => $CONF{BG_FRAME}
);

my $scale_fontsize = $topwin->Scale(
	-bg => $CONF{BG_FRAME},
	-activebackground => 'red',
	-highlightbackground => $CONF{BG_FRAME},
	-fg => 'white',
	-from => 6,
	-to => 14,
	-orient => 'horizontal',
	-font => 'Fixed 6 normal',
	-borderwidth => 0,
	-showvalue => 0,
	-label => 'Font scaling',
	-width => 20,
	-length => 100,
	-resolution => 1,
	-sliderlength => 15,
	-tickinterval => 2,
	-command => sub {
		my $size = shift;
		#print "Fixed $size Normal\n";
		$text_output->configure(-font => "Fixed $size normal");
		$text_output->see('end');
	}
);
$scale_fontsize->set(8);

my $scale_history = $topwin->Scale(
	-bg => $CONF{BG_FRAME},
	-activebackground => 'red',
	-highlightbackground => $CONF{BG_FRAME},
	-fg => 'white',
	-from => 0,
	-to => 1000,
	-orient => 'horizontal',
	-font => 'Fixed 6 normal',
	-borderwidth => 0,
	-showvalue => 0,
	-label => 'History Length',
	-width => 20,
	-length => 150,
	-resolution => 50,
	-sliderlength => 15,
	-tickinterval => 1000,
	-command => sub {
		my $len = shift;
		$len = 50 if ($len < 50);
		$CONF{'HISTORY'} = $len;
		print "History is now $len lines\n";
	}
);
$scale_history->set($CONF{'HISTORY'});

my $checkbox_pri = $topwin->Checkbutton(
	-font => "Fixed 6 normal",
	-text => "Display PRI",
	-fg => 'white',
	-bg => $CONF{BG_FRAME},
	-activebackground => $CONF{BG_FRAME},
	-activeforeground => 'white',
	-highlightbackground => $CONF{BG_FRAME},
	-highlightcolor => $CONF{BG_FRAME},
	-selectcolor => $CONF{BG_FRAME},
	-variable => \$CONF{DISPLAYPRI},
);

my $checkbox_wrap = $topwin->Checkbutton(
	-font => "Fixed 6 normal",
	-text => "Wrap text",
	-fg => 'white',
	-bg => $CONF{BG_FRAME},
	-activebackground => $CONF{BG_FRAME},
	-activeforeground => 'white',
	-highlightbackground => $CONF{BG_FRAME},
	-highlightcolor => $CONF{BG_FRAME},
	-selectcolor => $CONF{BG_FRAME},
	-variable => \$CONF{WRAPTEXT},
	-command => sub {
		if ($CONF{WRAPTEXT}) {
			#print "wrapping on\n";
			$text_output->configure(-wrap => 'char');
			$text_output->see('end');
		} else {
			#print "no wrapping\n";
			$text_output->configure(-wrap => 'none');
			$text_output->see('end');
		}
	}
);


# handle resize events
$botwin-> bind('<Configure>' => 
	sub {
		$text_output->see('end');
		#my $w = shift;
		#print "botwin now ",$w-> Width," x ",$w->Height," pixels\n";
	}
);


################################################################################
#  Grid Layout
################################################################################

# Frames in main window

$topwin->grid(-row => 0, -column => 0, -sticky => "ew");
$hidewin->grid(-row => 1, -column => 0, -sticky => "ew");
$botwin->grid(-row => 2, -column => 0, -sticky => "nsew");
$mw->gridColumnconfigure(0, -weight => 1);
$mw->gridRowconfigure(2, -weight => 1);

# topwin frame
$label_filter->grid(-row => 0, -column => 0, -sticky => "e");
$entry_filter->grid(-row => 0, -column => 1, -sticky => "w");
$button_apply->grid(-row => 0, -column => 2, -sticky => "w");
$button_clearfilter->grid(-row => 0, -column => 3, -sticky => "w");

$button_clearoutput->grid(-row => 0, -column => 4);

$button_options->grid(-row => 0, -column => 5);
$checkbox_pri->grid(-row => 0, -column => 6, -sticky => "ew");
$checkbox_wrap->grid(-row => 0, -column => 7, -sticky => "ew");

$scale_fontsize->grid(-row => 0, -column => 8, -sticky => "ew");

$button_quit->grid(-row => 0, -column => 9, -sticky => "e");
#$scale_history->grid(-row => 0, -column => 8, -sticky => "e"); # save this for a configuration menu





# hide button frame
$label_filterapplied->grid(-row => 0, -column => 0, -sticky => "w");
$label_listeninfo->grid(-row => 0, -column => 1, -sticky => "ew");
$button_toggledisplay->grid(-row => 0, -column => 2, -sticky => "e");


#####################
# main output frame
$text_output->grid(-row => 0, -column => 0, -padx => 5, -pady => 5, -sticky => "nsew");
$botwin->gridColumnconfigure(0, -weight => 1);
$botwin->gridRowconfigure(0, -weight => 1);

# set resize weight on all cells in the grid
my ($columns, $rows) = $topwin->gridSize( );
for (my $i = 0; $i < $columns; $i++) {
  $topwin->gridColumnconfigure($i, -weight => 1);
}
for (my $i = 0; $i < $rows; $i++) {
  $topwin->gridRowconfigure($i, -weight => 1);
}

# assign focus to the main entry item
$entry_filter->focus;


################################################################################
#  Timers
################################################################################



# see if any new messages have arrived
my $timer = $topwin->repeat(25, sub {
		my @ready = $selector->can_read(0.01);
		foreach my $sock (@ready) {
			my $input;

			#my ($port, $ipaddr) = sockaddr_in($sock->peername);
			#$ipaddr = join('.',unpack("C4",$ipaddr));
			#print "Accepting message from $ipaddr\n";

			# RFC 3164 says syslog messages must be no longer than 1024 bytes
			$sock->recv($input,1024) or warn "Cannot read from socket: $!\n";
			chomp($input); 

			#
			# only proceed if the message matches the filter; not case sensitive
			#
			eval { keys %$fhash }; # reset the 'each' cursor; VERY important
			my $skip = 0; my $orcount = 0; my $orexists = 0;
			while (my ($word,$op) = each %$fhash) {
				#print ",";
				if ($op eq 'NOT') { # NOT
					if ($input =~ /$word/i) {
						#print "\tskipping, $word is contained\n";
						$skip = 1;
						last;
					}
				} elsif ($op eq 'AND') { # AND
					if ($input !~ /$word/i) {
						#print "\tskipping, $word is NOT contained\n";
						$skip = 1;
						last;
					}
				} elsif ($op eq 'OR') { # OR
					$orexists = 1;
					if ($input =~ /$word/i) {
						#print "\tcontinuing, $word is contained\n";
						$orcount += 1 
					}
				} else { # error handling
					print "\tunknown operator\n";
				}
					
			}
			next if ($skip == 1);
			if (($orcount == 0) and ($orexists == 1)) {
				#print "\tskipping, none of the OR values are contained\n";
				next;
			}

			#
			# parse the major syslog message parameters per the RFC; PRI, date & time, message
			#
			my $pri = my $hdr = my $msg = "";
			if ($input =~ /^\<(\d+)\>(\S+ +\d+ \d\d:\d\d:\d\d) (.*)/) {
				$pri = $1;
				$hdr = $2;
				$msg = $3;
			} else {
				$msg = $input;
			}
			
			# parse out the priority and facility
			my $priority = 0;
			my $facility = 0;
			$priority = $pri % 8;
			$facility = int($pri - $priority)/20;
			my $content_tag = 'white';
			if ($priority < 3) {
				$content_tag = 'red' 
			} elsif ($priority == 3) {
				$content_tag = 'orange';
			} elsif ($priority == 4) {
				$content_tag = 'yellow';
			}

			$msg =~ s/Forwarded from //;
			my $field1 = my $field2 = my $field3 = "";
			my $content = $msg;
			#print "$msg\n";
			# highlight the first three multi-word fields prefixed with a colon
			if ($content =~ /^(\S+[^:]): (.*)/) {
				$field1 = $1;
				$content = $2;
			} elsif ($content =~ /^(\S+ \S+[^:]): (.*)/) {
				$field1 = $1;
				$content = $2;
			}

			if ($content =~ /^(\S+[^:]): (.*)/) {
				$field2 = $1;
				$content = $2;
			} elsif ($content =~ /^(\S+ \S+[^:]): (.*)/) {
				$field2 = $1;
				$content = $2;
			}

			if ($content =~ /^(\S+[^:]): (.*)/) {
				$field3 = $1;
				$content = $2;
			} elsif ($content =~ /^(\S+ \S+[^:]): (.*)/) {
				$field3 = $1;
				$content = $2;
			}
				

			# all we really want at this point is the time and msg
			$text_output->insert('end', "$hdr  ");
			$text_output->insert('end', sprintf("%s.%s ", $facilities[$facility], $priorities[$priority])) if ($CONF{DISPLAYPRI});
			$text_output->insert('end', "$field1: ", 'blue') if ($field1 ne "");
			$text_output->insert('end', "$field2: ", 'purple') if ($field2 ne "");
			$text_output->insert('end', "$field3: ", 'green') if ($field3 ne "");
			$text_output->insert('end', "$content\n", $content_tag);
			$text_output->see('end');

			# clean up old lines from output window
			my $idx = $text_output->index('current');
			if (int($idx) > $CONF{'HISTORY'}) {
				#printf("deleting %d lines\n", $idx - $CONF{'HISTORY'});
				$text_output->delete("1.0", sprintf("%d.0", $idx - $CONF{'HISTORY'}));
			}

			#configure scrollbars if it hasn't been done already
			configScrollbars($text_output);
			
	}

} );



################################################################################
#  Main Loop
################################################################################

# execute main window loop
MainLoop;

$sock_server->close;



################################################################################
# Subroutines
################################################################################

sub udpListener {
	my $host = shift;
	my $port = shift;
	my $phost = $host;
	$phost = '*' unless (defined $phost);

	# set host to undef to use INADDR_ANY
	my $sock = IO::Socket::INET->new(
		LocalAddr => $host,
		LocalPort => $port,
		Proto => 'udp',
		#Listen => 2,
	);
	die "Could not listen on $phost:$port - $@" unless (defined $sock);
	return $sock;
}
